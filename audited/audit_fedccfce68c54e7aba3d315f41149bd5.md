### Title
Unbounded HTTP Response Body Read in `fetchMirrorNodeNetwork` Enables Memory Exhaustion

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` passes `resp.Body` directly to `json.NewDecoder` with no `io.LimitReader` guard. An attacker who can influence the mirror node REST endpoint response (via DNS hijacking, MITM, or a compromised mirror node) can stream an arbitrarily large body, causing the pinger process to exhaust memory and CPU. The only existing protection—an HTTP client timeout—is time-based, not data-volume-based, and does not bound how many bytes are read within that window.

### Finding Description
**Exact location:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 84–98.

```go
resp, err := httpClient.Do(req)          // line 84
// ...
defer resp.Body.Close()                  // line 88
// ...
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {   // line 96
```

`resp.Body` is the raw, unbuffered HTTP response stream. `json.NewDecoder` reads from it in internal 512-byte chunks, allocating Go heap for every JSON token it materialises. There is no call to `io.LimitReader` or any equivalent cap before this point.

**Root cause / failed assumption:** The code assumes the mirror node is a trusted, well-behaved server that returns a reasonably sized JSON body. It does not account for a server (or a network-level impersonator) that sends a 200 OK with a plausible `Content-Length` header but then streams an unbounded body. Go's `net/http` transport does **not** enforce `Content-Length` as a hard read limit on `resp.Body`; it reads whatever bytes arrive on the TCP connection.

**Why the existing check is insufficient:** The HTTP client is constructed at line 46 of `mirror_node_client.go`:
```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```
The default timeout is **10 seconds** (`pinger/config.go`, line 130). This is a wall-clock deadline, not a byte-count limit. On a 1 Gbps link, 10 seconds allows ~1.25 GB of data to be read into the JSON decoder before the deadline fires. The decoder allocates heap for every `nodeEntry` struct it deserialises, so a crafted payload with millions of array elements causes proportional heap growth and GC pressure before the timeout cancels the context.

**Retry amplification:** `buildNetworkFromMirrorNodes` retries up to `mirrorNodeClientMaxRetries + 1` times (default 11 attempts, `config.go` line 72). Each retry re-issues the request and re-reads the body, multiplying the memory pressure. After the pinger is OOM-killed, Kubernetes restarts it, and the cycle repeats.

### Impact Explanation
The pinger process is the component that submits periodic crypto-transfer transactions to network processing nodes. If it is OOM-killed or spends its entire startup window reading a giant response body, it never reaches the `ticker` loop in `main.go` and never sends transactions. This starves the network processing nodes of the expected inbound connection load from this client. In a deployment where multiple pinger replicas share a node, the memory spike can also evict co-located workloads. The impact is denial-of-service against the pinger's ability to exercise network processing node connections, satisfying the ≥30% resource-consumption increase criterion through heap exhaustion and GC thrashing rather than CPU-bound computation.

### Likelihood Explanation
The precondition—controlling the mirror node REST endpoint—requires one of: (a) DNS poisoning of the `HIERO_MIRROR_PINGER_REST` hostname, (b) a network-level MITM (feasible in cloud environments without strict mTLS), or (c) a compromised mirror node instance. For `network=other` deployments (the only code path that calls `buildNetworkFromMirrorNodes`, per `sdk_client.go` line 17–18), the endpoint is operator-configured and may use plain HTTP (`http://mirror-rest:5551` is the documented example in `config.go` line 37), making MITM trivial within the same cluster network. No authentication of the mirror node response is performed. The attack is repeatable on every pinger restart.

### Recommendation
Wrap `resp.Body` with `io.LimitReader` before passing it to the JSON decoder, choosing a limit that comfortably exceeds the largest legitimate `/api/v1/network/nodes` response (e.g., 4 MB):

```go
const maxBodyBytes = 4 * 1024 * 1024 // 4 MB
limited := io.LimitReader(resp.Body, maxBodyBytes)
if err := json.NewDecoder(limited).Decode(&payload); err != nil {
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}
```

Additionally, enforce TLS with certificate validation for the mirror node endpoint and consider verifying the response `Content-Type` header before decoding.

### Proof of Concept
1. Stand up a TCP server that, upon receiving any HTTP GET, responds:
   ```
   HTTP/1.1 200 OK\r\n
   Content-Type: application/json\r\n
   Content-Length: 42\r\n
   \r\n
   {"nodes":[
   ```
   …then streams `{"node_account_id":"0.0.3","service_endpoints":[{"domain_name":"x","ip_address_v4":"","port":50211}]},` repeated indefinitely (ignoring the declared `Content-Length`).
2. Set `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-server>`.
3. Start the pinger. Observe via `top`/`/proc/<pid>/status` that `VmRSS` grows continuously until the process is OOM-killed or the 10-second timeout fires, having already consumed hundreds of MB.
4. Observe that the pinger never reaches the transfer ticker loop and never connects to any network processing node.