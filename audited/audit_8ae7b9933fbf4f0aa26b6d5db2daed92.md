### Title
Persistent HTTP 429 from Mirror REST Endpoint Exhausts Retry Loop, Blocking Pinger Initialization

### Summary
`buildNetworkFromMirrorNodes()` in `pinger/mirror_node_client.go` treats HTTP 429 as a retryable error and applies exponential backoff between attempts. An attacker who controls the configured mirror REST endpoint can return HTTP 429 on every request, forcing the function to exhaust all `cfg.mirrorNodeClientMaxRetries` retries with full backoff delays before returning a fatal error, causing `main()` to terminate the pinger process via `log.Fatalf`.

### Finding Description
**Code path:**

In `fetchMirrorNodeNetwork()` ( [1](#0-0) ):
```go
if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
    return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
}
```
HTTP 429 sets `retry = true`.

In `buildNetworkFromMirrorNodes()` ( [2](#0-1) ):
```go
for attempt := 1; attempt <= attempts; attempt++ {
    network, retry, err := fetchMirrorNodeNetwork(ctx, httpClient, url)
    ...
    if !retry || attempt == attempts { break }
    backoff := cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))
    select { ... case <-time.After(backoff): }
}
return nil, lastErr
```
With defaults (`mirrorNodeClientMaxRetries=10`, `mirrorNodeClientBaseBackoff=500ms`), the cumulative backoff is: 500ms + 1s + 2s + 4s + 8s + 16s + 32s + 64s + 128s + 256s ≈ **511.5 seconds (~8.5 minutes)** before returning an error.

This error propagates through `newClient()` ( [3](#0-2) ) back to `main()` ( [4](#0-3) ):
```go
client, err := newClient(cfg)
if err != nil {
    log.Fatalf("client error: %v", err)
}
```
`log.Fatalf` calls `os.Exit(1)`, permanently terminating the pinger.

**Root cause:** There is no cap on total retry duration, no circuit breaker, and no distinction between a legitimately rate-limited trusted endpoint and a persistently adversarial one. The failed assumption is that the mirror REST endpoint is a cooperative, trusted service.

### Impact Explanation
When `network=other` is configured, the pinger cannot initialize its Hiero network map without a successful response from the mirror REST endpoint. A persistent 429 response causes an ~8.5-minute blocking delay (with default config, unbounded with higher `mirrorNodeClientMaxRetries`) followed by process termination. The pinger never writes `/tmp/ready` ( [5](#0-4) ), so liveness/readiness probes fail and the service is permanently unavailable. No economic damage occurs, but the monitoring/pinging function of the service is completely disabled — consistent with the "Medium griefing" scope classification.

### Likelihood Explanation
The precondition requires the attacker to control the HTTP responses from the configured `HIERO_MIRROR_PINGER_REST` endpoint. Realistic vectors include: (1) operating a public mirror node that a pinger operator chooses to use, (2) DNS hijacking or MITM on the network path between the pinger and the mirror node, or (3) compromising the mirror-rest service in a shared deployment. The `network=other` mode is explicitly designed for custom/private deployments, making this scenario operationally plausible. The attack is trivially repeatable — returning 429 requires no special knowledge and can be automated.

### Recommendation
1. **Add a total-duration deadline** for the entire retry loop (e.g., a `context.WithTimeout` wrapping the loop), independent of per-attempt count, so the pinger fails fast rather than blocking for minutes.
2. **Cap exponential backoff** with a maximum per-attempt ceiling (e.g., `min(backoff, 30s)`) to prevent unbounded delay growth.
3. **Distinguish 429 from 5xx**: for 429, respect the `Retry-After` header if present, but apply a hard cap; do not treat it identically to transient server errors.
4. **Consider non-fatal initialization failure**: instead of `log.Fatalf`, retry initialization in the background so the process remains alive and can recover when the mirror node becomes cooperative.

### Proof of Concept
1. Deploy a simple HTTP server that always responds `HTTP/1.1 429 Too Many Requests` to any `GET /api/v1/network/nodes` request.
2. Configure the pinger: `HIERO_MIRROR_PINGER_NETWORK=other`, `HIERO_MIRROR_PINGER_REST=http://<attacker-server>`.
3. Start the pinger. Observe it makes 11 attempts with exponential backoff (500ms, 1s, 2s, … 256s).
4. After ~511 seconds, the pinger logs `client error: attempt 11/11: GET ... returned 429 Too Many Requests` and exits with code 1.
5. The `/tmp/ready` file is never created; readiness probes fail; the pinger never performs any transfers.

### Citations

**File:** pinger/mirror_node_client.go (L52-69)
```go
	for attempt := 1; attempt <= attempts; attempt++ {
		network, retry, err := fetchMirrorNodeNetwork(ctx, httpClient, url)
		if err == nil {
			return network, nil
		}

		lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
		if !retry || attempt == attempts {
			break
		}

		backoff := cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
```

**File:** pinger/mirror_node_client.go (L90-92)
```go
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
```

**File:** pinger/sdk_client.go (L18-21)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
```

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```

**File:** pinger/main.go (L47-49)
```go
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```
