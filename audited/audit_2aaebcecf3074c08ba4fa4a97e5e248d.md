### Title
Unbounded HTTP Response Body Allows Memory Exhaustion via Malicious Mirror REST Endpoint

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` decodes the mirror REST response with no body-size limit and no length validation on `domain_name` fields. An attacker who can influence the mirror REST response — via MITM on the plain-HTTP connection or by operating a malicious endpoint — can return a crafted JSON payload with arbitrarily many nodes, each carrying arbitrarily long `domain_name` strings, causing the pinger process to allocate unbounded memory until it is OOM-killed.

### Finding Description
**Exact code path:**

`newClient()` (`sdk_client.go:18`) → `buildNetworkFromMirrorNodes()` (`mirror_node_client.go:36`) → `fetchMirrorNodeNetwork()` (`mirror_node_client.go:74`).

Inside `fetchMirrorNodeNetwork()`:

```go
// mirror_node_client.go:84-98
resp, err := httpClient.Do(req)
...
defer resp.Body.Close()
...
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
```

`resp.Body` is passed directly to `json.NewDecoder` with **no** `http.MaxBytesReader` wrapper. The JSON decoder will read and allocate memory for the entire response body, regardless of size.

After decoding, every `domain_name` is used without a length check:

```go
// mirror_node_client.go:113-123
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)   // no length limit
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)
    }
    if host == "" || ep.Port == 0 {
        continue
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId              // stored in map, no cap
}
```

`strings.TrimSpace` and the empty-string check are the only guards — neither bounds the string length. `net.JoinHostPort` allocates a new string of `len(host) + len(port) + 3` bytes per entry. All resulting strings are inserted into the `network` map with no cap on the number of entries.

**Root cause / failed assumption:** The code assumes the mirror REST endpoint is trusted and returns a reasonably sized response. There is no defense-in-depth size limit at the HTTP layer or at the field level.

**Why the existing check is insufficient:** The `http.Client` timeout (`cfg.mirrorNodeClientTimeout`, default 10 s) limits transfer *time* but not transfer *size*. On a local or fast network, hundreds of megabytes can be transferred within 10 seconds. The timeout does not prevent memory exhaustion.

### Impact Explanation
The pinger process is OOM-killed, stopping all periodic Hiero transfers it is responsible for. Because `newClient()` is called once at startup (`main.go:41`) and the process exits on error, a single crafted response permanently disables the pinger until it is manually restarted. In a Kubernetes deployment the liveness probe (`/tmp/alive`) stops being updated, triggering a pod restart loop that keeps the pinger unavailable as long as the malicious endpoint is reachable. Severity is medium: no funds are at risk, but the monitoring/liveness function of the pinger is completely disrupted.

### Likelihood Explanation
The attack surface is limited to `network=other` deployments where `HIERO_MIRROR_PINGER_REST` points to an attacker-reachable endpoint. The default example URL (`http://mirror-rest:5551`) uses plain HTTP, making network-level MITM straightforward for any attacker on the same L2 segment or upstream network path. No credentials or special privileges are required to serve a crafted HTTP response once the attacker is on-path. The attack is repeatable: every pinger restart re-fetches the endpoint, so the attacker can sustain the disruption indefinitely.

### Recommendation
1. **Wrap the response body with a size limit before decoding:**
   ```go
   const maxBodyBytes = 10 * 1024 * 1024 // 10 MB
   resp.Body = http.MaxBytesReader(nil, resp.Body, maxBodyBytes)
   ```
2. **Validate `domain_name` length** before use (RFC 1035 max label 63 bytes, FQDN 253 bytes):
   ```go
   if len(host) > 253 {
       continue
   }
   ```
3. **Cap the number of entries** accepted into the `network` map (e.g., 1000 nodes × 10 endpoints).
4. **Use HTTPS** for the mirror REST endpoint to prevent MITM.

### Proof of Concept
1. Stand up an HTTP server at the address configured in `HIERO_MIRROR_PINGER_REST`.
2. Serve the following JSON (pseudocode — generate programmatically):
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           { "domain_name": "<64KB random string>", "port": 50211 },
           ... repeat 10000 times ...
         ]
       },
       ... repeat 1000 nodes ...
     ],
     "links": { "next": null }
   }
   ```
   Total payload ≈ 640 GB (or smaller with compression); even a 500 MB payload saturates a typical container's memory limit.
3. Start the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-server>`.
4. Observe the pinger process being OOM-killed during `json.Decode` or map population, before it ever reaches `hiero.ClientForNetwork`.