### Title
Startup-Window Mirror REST Poisoning Causes Permanent Stale Network Map (network=other)

### Summary
When `cfg.network == "other"`, `newClient()` calls `buildNetworkFromMirrorNodes()` exactly once at process startup over an unauthenticated HTTP connection, and the resulting network map is never refreshed for the lifetime of the pinger. An attacker with network-level access (DNS spoofing, ARP poisoning, BGP hijack, or any MITM on an HTTP endpoint) who intercepts only that single startup request can return a partial node list, permanently excluding ≥30% of consensus nodes from all subsequent transactions the pinger ever submits.

### Finding Description

**Exact code path:**

`pinger/main.go` line 41 calls `newClient(cfg)` once and stores the result in `client`, which is then used for the entire process lifetime in the ticker loop (lines 54–70). [1](#0-0) 

Inside `newClient()`, the `"other"` branch calls `buildNetworkFromMirrorNodes()` once and passes the result directly to `hiero.ClientForNetwork(netmap)` with no subsequent refresh. [2](#0-1) 

`buildNetworkFromMirrorNodes()` constructs a plain `http.Client` (no custom TLS config, no certificate pinning, no mutual TLS) and issues a single unauthenticated GET to `cfg.mirrorRest + "/api/v1/network/nodes"`. [3](#0-2) 

`fetchMirrorNodeNetwork()` decodes the JSON body and builds the map. The **only** guard against a poisoned response is the empty-map check at lines 127–129 — an attacker who returns even one valid node entry bypasses it entirely. [4](#0-3) 

Additionally, `fetchMirrorNodeNetwork` parses `links.next` but **never follows pagination**, so even a legitimate mirror node serving multiple pages will produce an incomplete map — and an attacker can exploit this same truncation deliberately. [5](#0-4) 

**Root cause / failed assumption:** The code assumes the mirror REST endpoint is trusted and reachable over a secure channel, and that a one-time fetch at startup is sufficient. Neither assumption is enforced: the URL scheme is not validated (HTTP is accepted), there is no response signature or HMAC, and there is no periodic re-fetch to self-heal.

**Exploit flow:**
1. Attacker positions themselves to intercept HTTP traffic between the pinger and `cfg.mirrorRest` (DNS spoofing, ARP poisoning on the same L2 segment, or BGP prefix hijack for public IPs).
2. Pinger starts; `newClient()` issues `GET http://<mirror-rest>/api/v1/network/nodes`.
3. Attacker intercepts and responds with a valid JSON envelope containing only a subset of nodes (e.g., 3 of 10), omitting ≥30%.
4. `buildNetworkFromMirrorNodes()` returns the truncated map; `hiero.ClientForNetwork(netmap)` is called with it.
5. The pinger runs indefinitely, routing all transactions only through the attacker-chosen subset of nodes. The excluded nodes receive zero traffic from this pinger for the entire process lifetime.

### Impact Explanation
All consensus transactions submitted by the pinger for its entire runtime are routed exclusively to the attacker-selected subset of nodes. Nodes excluded from the map receive no pings, which can cause monitoring/liveness systems to falsely report those nodes as unhealthy or unreachable. If the pinger is used as a health signal for operational decisions (e.g., alerting, auto-remediation), excluding ≥30% of nodes constitutes a partial network-visibility blackout matching the stated severity scope. Because the client is never re-initialized, the only recovery is a full process restart — which the attacker can repeat.

### Likelihood Explanation
The attack requires network-level interception, not application-level credentials. For deployments where `mirrorRest` is an `http://` URL (common in internal Kubernetes or Docker Compose setups where TLS is terminated at an ingress), any pod on the same cluster network or any host on the same L2 segment can perform ARP/DNS poisoning. The attack window is the single HTTP request at startup — a narrow but fully predictable moment (process start). The attacker does not need to sustain the interception; one poisoned response is sufficient for permanent effect. Repeatability is high: every pinger restart re-opens the same window.

### Recommendation
1. **Enforce HTTPS with certificate validation** for `mirrorRest`; reject `http://` URLs at config load time.
2. **Implement periodic network map refresh** — re-call `buildNetworkFromMirrorNodes()` on a configurable interval and update the client's node list, so a poisoned startup does not persist indefinitely.
3. **Follow pagination** (`links.next`) to ensure the full node list is always fetched, removing the truncation vector.
4. **Validate minimum node count** against a configurable floor (e.g., fail startup if fewer than N nodes are returned), making partial-list poisoning detectable.
5. **Cross-validate** the returned node list against a secondary source or a locally pinned baseline when operating in `other` mode.

### Proof of Concept
```
# 1. Stand up a rogue HTTP server that returns only 1 of N real nodes:
cat > fake_mirror.py << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"nodes": [
            {"node_account_id": "0.0.3",
             "service_endpoints": [{"ip_address_v4": "1.2.3.4", "port": 50211}],
             "grpc_proxy_endpoint": None}
        ], "links": {"next": None}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
python3 fake_mirror.py &

# 2. DNS-spoof or /etc/hosts-redirect the real mirrorRest hostname to 127.0.0.1:8080
# (or simply set HIERO_MIRROR_PINGER_REST=http://127.0.0.1:8080 to simulate)

# 3. Start the pinger with network=other pointing at the rogue server:
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://127.0.0.1:8080 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# 4. Observe: pinger starts successfully (non-empty map passes the guard),
#    logs show only node 0.0.3 in the network map.
#    All subsequent transactions for the process lifetime target only that node.
#    All other real nodes are permanently excluded with no error or warning.
```

### Citations

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```

**File:** pinger/sdk_client.go (L17-22)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/mirror_node_client.go (L17-22)
```go
type nodesEnvelope struct {
	Nodes []nodeEntry `json:"nodes"`
	Links struct {
		Next *string `json:"next"`
	} `json:"links"`
}
```

**File:** pinger/mirror_node_client.go (L46-55)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}

	attempts := max(cfg.mirrorNodeClientMaxRetries + 1, 1)

	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		network, retry, err := fetchMirrorNodeNetwork(ctx, httpClient, url)
		if err == nil {
			return network, nil
```

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```
