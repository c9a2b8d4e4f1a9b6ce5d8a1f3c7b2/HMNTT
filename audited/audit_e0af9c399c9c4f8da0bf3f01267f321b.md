### Title
Unbounded Response Body in `fetchMirrorNodeNetwork()` Enables OOM via Malicious Mirror Node

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` passes `resp.Body` directly to `json.NewDecoder(...).Decode()` with no size cap. An attacker who controls the configured mirror node REST endpoint can return a response body of arbitrary size, causing the Go runtime to allocate unbounded heap memory and crash the pinger process via OOM. The only existing guard — an HTTP client timeout — limits time but not bytes-in-flight, so a fast server on a local or high-bandwidth network can exhaust memory well within the timeout window.

### Finding Description
**Exact code path:**
`pinger/mirror_node_client.go`, function `fetchMirrorNodeNetwork()`, line 96:

```go
// line 96 — no LimitReader, no MaxBytesReader
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
```

**Root cause:** `resp.Body` is an unbounded `io.ReadCloser`. `json.NewDecoder` reads from it in 512-byte internal chunks, but it will keep reading until EOF or a decode error. Because the target struct (`nodesEnvelope`) contains a slice (`[]nodeEntry`), the decoder will happily allocate one `nodeEntry` per JSON array element, growing the heap without limit.

**Failed assumption:** The code assumes the mirror node REST server is trusted and will return a reasonably-sized response. No defensive cap is applied.

**Why existing checks are insufficient:**

- **HTTP client timeout** (line 46, `cfg.mirrorNodeClientTimeout`): limits wall-clock duration, not bytes transferred. On a 1 Gbps LAN, a 30-second timeout still allows ~3.75 GB of data to be streamed and decoded into memory.
- **Status-code check** (lines 90–93): only rejects non-2xx responses; a 200 OK with a multi-gigabyte body passes straight through to the decoder.
- **No `io.LimitReader` / `http.MaxBytesReader`** anywhere in the call chain.

**Exploit flow:**
1. Attacker controls the mirror node REST server (compromised server, DNS hijack, MITM on plain HTTP, or operator misconfiguration pointing pinger at an attacker-controlled host).
2. Pinger calls `fetchMirrorNodeNetwork()` → issues `GET /api/v1/network/nodes`.
3. Attacker's server responds `200 OK` with a JSON body containing millions of `nodeEntry` objects (or a single field with a multi-GB string value).
4. `json.NewDecoder(resp.Body).Decode(&payload)` reads the entire stream, allocating heap memory proportional to the body size.
5. Go runtime OOM-kills the pinger process (or the host kernel OOM-kills it), causing a denial of service.

### Impact Explanation
- **Availability:** Complete crash of the pinger process. Because `buildNetworkFromMirrorNodes` is called at startup to build the Hiero network map, a crash here prevents the pinger from ever becoming operational, or kills it mid-run if the network is refreshed.
- **Severity:** High — a single HTTP response can take down the monitoring component with no authentication required beyond network access to the mirror node endpoint.

### Likelihood Explanation
- The mirror node REST URL is operator-configured, but the threat is realistic in several scenarios: DNS poisoning of the mirror node hostname, a compromised mirror node (the pinger explicitly trusts whatever server is at that URL), or an insider/misconfiguration pointing the pinger at a hostile host.
- No special privileges are needed once the attacker can serve HTTP responses at the configured URL.
- The attack is trivially repeatable: every retry loop iteration (`attempts` times, line 52) re-issues the request, each time potentially allocating more memory before the process dies.

### Recommendation
Wrap `resp.Body` with a size-limiting reader before decoding. A reasonable upper bound for the `/network/nodes` response (e.g., 10 MB) is orders of magnitude larger than any legitimate payload:

```go
const maxBodyBytes = 10 << 20 // 10 MiB
limited := io.LimitReader(resp.Body, maxBodyBytes+1)
if err := json.NewDecoder(limited).Decode(&payload); err != nil {
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}
// Optionally detect truncation:
// if n, _ := io.Copy(io.Discard, limited); n > 0 { /* body was truncated */ }
```

Alternatively, use `http.MaxBytesReader(nil, resp.Body, maxBodyBytes)` which also causes the HTTP transport to abort the connection once the limit is hit, saving bandwidth.

### Proof of Concept
1. Stand up a minimal HTTP server that responds to any `GET` request with:
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   {"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"domain_name":"x","port":50211}
   ```
   …followed by millions of additional `nodeEntry` JSON objects (or a single `"node_account_id"` value that is gigabytes long), then `]}`.
2. Configure the pinger's `mirrorRest` to point at this server.
3. Start the pinger. Observe heap growth via `top`/`htop` until the process is OOM-killed or panics with `runtime: out of memory`. [1](#0-0) [2](#0-1)

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L90-98)
```go
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}

	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
```
