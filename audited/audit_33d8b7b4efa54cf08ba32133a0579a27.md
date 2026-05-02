### Title
Incomplete Pagination in `fetchMirrorNodeNetwork()` Allows MITM Attacker to Bias Transaction Routing via Crafted Partial Node List

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` parses the `Links.Next` pagination field from the mirror node REST response but never follows it. A network-adjacent attacker who can intercept the unencrypted HTTP response can return a crafted first page containing only attacker-chosen consensus nodes while setting `Links.Next` to a non-null value, causing the pinger to build a permanently incomplete node map. All subsequent transactions are then routed exclusively through the attacker-selected nodes for the lifetime of the process.

### Finding Description
**Exact code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–132.

The `nodesEnvelope` struct at lines 17–22 declares `Links.Next *string`, which is populated during JSON decoding at line 96. After decoding, the function iterates only over `payload.Nodes` (line 102) and returns as soon as `len(network) > 0` (lines 127–131). `Links.Next` is never inspected or followed. There is no assertion that the response represents the complete node set.

`buildNetworkFromMirrorNodes()` (lines 36–72) calls `fetchMirrorNodeNetwork()` once per retry attempt and returns the first successful result. The returned `netmap` is passed directly to `hiero.ClientForNetwork(netmap)` in `sdk_client.go` line 22, permanently fixing the SDK's node pool for the entire process lifetime.

**Root cause:** The code assumes a single HTTP response contains the full node list. The failed assumption is that `len(network) > 0` is a sufficient completeness check — it is not; a paginated response with one node on the first page satisfies this check while omitting all remaining nodes.

**Exploit flow:**
1. Attacker intercepts the HTTP GET to `/api/v1/network/nodes` (plain HTTP is permitted by config; `http.Client` at line 46 has no TLS enforcement or certificate pinning).
2. Attacker returns a crafted JSON body: one or two real node entries (to pass the `len(network) > 0` guard) plus `"links": {"next": "/api/v1/network/nodes?limit=25&node.id=gt:0.0.5"}`.
3. `fetchMirrorNodeNetwork()` decodes the body, builds a one-entry `network` map, sees `len(network) == 1 > 0`, and returns `(network, false, nil)` — success.
4. `newClient()` calls `hiero.ClientForNetwork(netmap)` with the single-entry map.
5. Every `submitWithRetry()` call in the ticker loop routes its `TransferTransaction` exclusively through the attacker-chosen node.

**Why existing checks are insufficient:**
- The `len(network) == 0` guard (line 127) only rejects a completely empty response; it does not detect a deliberately truncated one.
- The retry loop in `buildNetworkFromMirrorNodes()` retries on network errors and 5xx/429 responses, but a 200 OK with a partial body is accepted immediately and terminates the retry loop.
- No TLS certificate pinning or HTTPS enforcement exists on the `http.Client`.

### Impact Explanation
The pinger's entire transaction stream is permanently redirected to attacker-chosen consensus nodes for the lifetime of the process (until restart). This alters the distribution of transactions recorded in mirror node history, enabling selective omission or concentration of pinger-originated transactions on specific nodes. While no funds are directly stolen (the operator key is still required to sign), the integrity of the mirror node's transaction history is compromised: monitoring, alerting, and analytics that rely on uniform node coverage will produce skewed results. Severity is **Medium** given the absence of direct fund loss but meaningful integrity impact on the monitoring infrastructure this pinger is designed to support.

### Likelihood Explanation
The attack requires a network-adjacent MITM position. In Kubernetes-based deployments (evidenced by `/tmp/alive` and `/tmp/ready` liveness/readiness probe files in `main.go`), the mirror REST URL is commonly configured as a plain `http://` in-cluster service address. Any attacker with access to the pod network (compromised sidecar, ARP spoofing on a flat network, or DNS poisoning of the in-cluster service name) can execute this attack. The attack is repeatable on every pinger restart and requires no credentials. The crafted response is a valid 200 OK JSON body, so no anomaly detection based on HTTP status codes will trigger.

### Recommendation
1. **Follow pagination**: After decoding each page, check `payload.Links.Next`. If non-nil and non-empty, issue a subsequent GET to that URL and merge results before returning. Enforce a maximum page count to prevent infinite loops.
2. **Enforce HTTPS with certificate verification**: Reject `http://` mirror REST URLs in `loadConfig()`, or configure the `http.Client` with a strict TLS config that verifies the server certificate against a pinned CA.
3. **Minimum node count check**: After building the network map, compare `len(network)` against a configurable minimum threshold (e.g., the known network size) and fail if the count is suspiciously low.
4. **Validate `Links.Next` is nil before returning**: Treat a non-nil `Links.Next` in the final accepted response as an error condition indicating an incomplete fetch.

### Proof of Concept
```
# 1. Stand up a fake mirror node HTTP server that returns a partial node list:
cat > fake_mirror.py << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "nodes": [{
                "node_account_id": "0.0.3",
                "service_endpoints": [{"ip_address_v4": "34.94.106.61", "port": 50211}],
                "grpc_proxy_endpoint": None
            }],
            "links": {"next": "/api/v1/network/nodes?limit=25&node.id=gt:0.0.3"}
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8080), H).serve_forever()
EOF
python3 fake_mirror.py &

# 2. Run the pinger pointed at the fake mirror:
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://127.0.0.1:8080 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# 3. Observe: pinger starts successfully, SDK client is built with only node 0.0.3.
#    All TransferTransactions are submitted exclusively to 34.94.106.61:50211.
#    The real nodes (0.0.4, 0.0.5, ...) are never contacted.
#    Links.Next is silently ignored; no error or warning is logged.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L17-22)
```go
type nodesEnvelope struct {
	Nodes []nodeEntry `json:"nodes"`
	Links struct {
		Next *string `json:"next"`
	} `json:"links"`
}
```

**File:** pinger/mirror_node_client.go (L44-46)
```go
	}

	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L95-131)
```go
	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}

	network := make(map[string]hiero.AccountID)

	for _, n := range payload.Nodes {
		if n.NodeAccountID == "" {
			continue
		}

		nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
		if err != nil {
			continue
		}

		// Use service_endpoints for node gRPC (what the SDK wants)
		for _, ep := range n.ServiceEndpoints {
			host := strings.TrimSpace(ep.DomainName)
			if host == "" {
				host = strings.TrimSpace(ep.IPAddressV4)
			}
			if host == "" || ep.Port == 0 {
				continue
			}

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
			network[addr] = nodeAccountId
		}
	}

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}

	return network, false, nil
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
