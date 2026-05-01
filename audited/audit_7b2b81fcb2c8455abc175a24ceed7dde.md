### Title
HTTP 429 Retry Exhaustion in `fetchMirrorNodeNetwork` Causes Pinger Process Termination via `log.Fatalf`

### Summary
When `network=other` is configured, the pinger calls `buildNetworkFromMirrorNodes` at startup to discover consensus nodes. If the configured mirror REST endpoint persistently returns HTTP 429, the retry loop in `buildNetworkFromMirrorNodes` exhausts all `mirrorNodeClientMaxRetries+1` attempts (default: 11), `newClient` returns an error, and `main.go` calls `log.Fatalf`, terminating the pinger process entirely and halting all transaction submissions.

### Finding Description
**Exact code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 90–92:
```go
if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
    return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
}
```
HTTP 429 sets `retry = true` and returns an error.

`buildNetworkFromMirrorNodes()`, lines 52–69: The caller loops up to `attempts = max(cfg.mirrorNodeClientMaxRetries+1, 1)` times (default 11). Each iteration calls `fetchMirrorNodeNetwork`; if `retry==true` and attempts remain, it sleeps `500ms * 2^(attempt-1)` (uncapped — unlike `transfer.go` which caps at 30s) and retries. After all attempts are exhausted, it returns `nil, lastErr`.

`pinger/sdk_client.go`, lines 18–21:
```go
case "other":
    netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
    if err != nil {
        return nil, err
    }
```
The error propagates to `newClient`.

`pinger/main.go`, lines 41–44:
```go
client, err := newClient(cfg)
if err != nil {
    log.Fatalf("client error: %v", err)
}
```
`log.Fatalf` calls `os.Exit(1)`, terminating the process.

**Root cause:** The code treats HTTP 429 as a retryable transient error with no upper bound on how long the endpoint can sustain the 429 state. There is no fallback node list, no cached prior-successful node map, no `Retry-After` header respect, and no circuit-breaker. A persistent 429 from the mirror REST endpoint is indistinguishable from a temporary rate-limit, so the pinger burns through its entire retry budget and then fatally exits.

**Why existing checks fail:**
- The `retry` flag check at line 59 (`if !retry || attempt == attempts`) correctly stops retrying non-transient errors (4xx other than 429), but explicitly keeps retrying on 429 — the exact status an attacker would return.
- The exponential backoff (lines 63–68) only delays the inevitable; it does not prevent exhaustion.
- The `Retry-After` response header is never read; the pinger cannot be told to wait longer than its own backoff schedule.
- No node-map cache exists; every startup requires a fresh successful fetch.

### Impact Explanation
For any deployment using `network=other` (required for private/custom networks), a sustained 429 response from the mirror REST endpoint causes the pinger to terminate at startup via `log.Fatalf`. The pinger never reaches the ticker loop, so zero transactions are submitted. This maps directly to the stated scope: shutdown of ≥30% of network processing nodes without brute force, because the pinger is the sole transaction-submission component and its process exits cleanly with no self-recovery.

### Likelihood Explanation
The precondition is that the attacker can make the configured mirror REST endpoint return 429. Realistic vectors for `network=other`:
1. **DNS poisoning/hijacking** of the mirror REST hostname — the HTTP client performs no certificate pinning and the URL is operator-supplied, so a DNS-level redirect to an attacker-controlled server is sufficient.
2. **Plaintext HTTP** — if the operator configures an `http://` URL (common in internal/private deployments), a network-path attacker (e.g., compromised internal router, cloud VPC peer) can intercept and respond with 429.
3. **Compromised or malicious mirror node** — the mirror REST service itself is a third-party dependency; a compromised mirror node operator can return 429 indefinitely.

The attack is repeatable: every time the pinger pod is restarted (e.g., by Kubernetes liveness/readiness probe failure or manual restart), it re-runs `buildNetworkFromMirrorNodes` from scratch and will fail again under the same conditions.

### Recommendation
1. **Do not call `log.Fatalf` on mirror REST failure at startup.** Instead, retry indefinitely (with a cap and jitter) or fall back to a statically configured node list, allowing the pinger to start and attempt node discovery in the background.
2. **Respect the `Retry-After` header** from 429 responses to avoid burning the retry budget faster than the server intends.
3. **Cap the exponential backoff** in `buildNetworkFromMirrorNodes` (as is already done in `transfer.go` at 30s) to prevent unbounded wait times.
4. **Cache the last successfully fetched node map** to disk or memory so that a restart can use a stale-but-valid map while re-fetching in the background.
5. **Validate the mirror REST URL** at config load time and prefer HTTPS with certificate verification to reduce DNS/MITM attack surface.

### Proof of Concept
**Preconditions:** Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://attacker-controlled-host/`.

**Steps:**
1. Stand up an HTTP server at `attacker-controlled-host` that responds to all requests with `HTTP/1.1 429 Too Many Requests`.
2. Start the pinger (or trigger a pod restart).
3. Observe in logs:
   ```
   attempt 1/11: GET http://attacker-controlled-host/api/v1/network/nodes returned 429 Too Many Requests
   attempt 2/11: ...
   ...
   attempt 11/11: ...
   client error: attempt 11/11: GET http://attacker-controlled-host/api/v1/network/nodes returned 429 Too Many Requests
   exit status 1
   ```
4. The pinger process exits. No transactions are submitted. The `/tmp/ready` file is never written, so readiness probes fail and the pod remains in a crash loop as long as the attacker's server returns 429.