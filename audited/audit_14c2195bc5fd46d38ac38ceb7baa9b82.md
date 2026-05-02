### Title
Unbounded Cumulative Initialization Delay via Network-Path Interception in `buildNetworkFromMirrorNodes`

### Summary
`buildNetworkFromMirrorNodes` is called with `context.Background()` (no deadline) and loops up to `mirrorNodeClientMaxRetries + 1` times, each attempt blocking for the full `mirrorNodeClientTimeout` on a stalled TCP connection, followed by exponential backoff. An attacker controlling the network path to the mirror REST endpoint can force each attempt to consume the full per-request timeout, producing a cumulative initialization delay exceeding 10 minutes with default settings — blocking all transaction submissions until initialization completes or fatally fails.

### Finding Description

**Exact code path:**

In `pinger/sdk_client.go` line 18, `buildNetworkFromMirrorNodes` is called with `context.Background()`:
```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
```
This context has no deadline and is never cancelled.

In `pinger/mirror_node_client.go` lines 46–69, the retry loop:
```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}   // default 10s
attempts := max(cfg.mirrorNodeClientMaxRetries + 1, 1)             // default 11

for attempt := 1; attempt <= attempts; attempt++ {
    network, retry, err := fetchMirrorNodeNetwork(ctx, httpClient, url)
    ...
    backoff := cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))
    select {
    case <-ctx.Done():   // ctx is context.Background() — NEVER fires
        return nil, ctx.Err()
    case <-time.After(backoff):
    }
}
```

In `fetchMirrorNodeNetwork` (lines 79–84), the HTTP request uses the per-request `http.Client.Timeout` but no independent overall deadline:
```go
req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
resp, err := httpClient.Do(req)
```

**Root cause:** There is no overall deadline wrapping the entire `buildNetworkFromMirrorNodes` call. The only bound is per-request (`http.Client.Timeout`). With `mirrorNodeClientMaxRetries=10` (default), the attacker can force 11 full-timeout hangs plus exponential backoff:

| Phase | Duration |
|---|---|
| 11 attempts × 10s timeout | 110s |
| Backoff sum (500ms×2^0 … 500ms×2^9) | ~511.5s |
| **Total** | **~621s (~10.4 min)** |

**Why existing checks fail:**
- `http.Client.Timeout` bounds each individual request but not the cumulative loop.
- The `ctx.Done()` branch in the backoff `select` is dead code because `context.Background()` never cancels.
- No circuit-breaker or overall wall-clock deadline exists on the initialization path.

### Impact Explanation
`newClient()` is called synchronously in `main()` before the readiness file `/tmp/ready` is written (line 47 of `main.go`). Until `newClient()` returns, the pinger submits zero transactions. With default settings, an attacker can delay initialization by ~621 seconds. The liveness heartbeat goroutine (writing `/tmp/alive` every 15s) continues independently, so the pod is not killed — it simply stalls silently. This constitutes a complete freeze of all transaction submissions for the duration of the attack, far exceeding 500% of any reasonable block-time equivalent.

### Likelihood Explanation
The precondition is controlling the network path between the pinger pod and the mirror REST endpoint. This is achievable by:
- **DNS poisoning** if `HIERO_MIRROR_PINGER_REST` uses a hostname (attacker returns their own IP)
- **ARP/BGP-level interception** in cloud or on-prem environments
- **A compromised intermediate proxy or load balancer**

The attacker needs no credentials, no authentication, and no knowledge of the operator key. They only need to accept the TCP connection and withhold the HTTP response. The attack is repeatable: every time the pinger pod restarts (e.g., after a crash or rolling deploy), the initialization sequence runs again and is equally vulnerable.

### Recommendation
1. **Add an overall deadline** to the initialization call in `sdk_client.go`:
   ```go
   initCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
   defer cancel()
   netmap, err := buildNetworkFromMirrorNodes(initCtx, cfg)
   ```
2. **Cap exponential backoff** to a maximum value (e.g., 10s) to prevent the backoff series from dominating total delay.
3. **Reduce default `mirrorNodeClientMaxRetries`** or add a configurable overall initialization timeout separate from the per-request timeout.

### Proof of Concept
1. Deploy the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-controlled-host>:80`.
2. On the attacker host, run a TCP listener that completes the TCP handshake but never sends any HTTP response:
   ```bash
   # Accept connection, send nothing
   nc -l -p 80
   ```
3. Observe that the pinger blocks in `buildNetworkFromMirrorNodes` for ~10s per attempt × 11 attempts, plus exponential backoff totaling ~621s.
4. Confirm `/tmp/ready` is never written during this period and no transactions are submitted.
5. Alternatively, achieve the same effect via DNS poisoning of the mirror REST hostname to point to the attacker's stalling server. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** pinger/sdk_client.go (L18-18)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
```

**File:** pinger/mirror_node_client.go (L46-69)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}

	attempts := max(cfg.mirrorNodeClientMaxRetries + 1, 1)

	var lastErr error

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

**File:** pinger/mirror_node_client.go (L79-84)
```go
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := httpClient.Do(req)
```

**File:** pinger/config.go (L72-95)
```go
	mirrorNodeClientMaxRetriesStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_MAX_RETRIES", "10")
	flag.Func("mirror-node-client-max-retries", "max retries for mirror node client requests", func(s string) error {
		v, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		cfg.mirrorNodeClientMaxRetries = v
		return nil
	})
	_ = flag.CommandLine.Set("mirror-node-client-max-retries", mirrorNodeClientMaxRetriesStr)

	mirrorNodeClientBaseBackoffStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_BASE_BACKOFF", "500ms")
	flag.DurationVar(
		&cfg.mirrorNodeClientBaseBackoff,
		"mirror-node-client-base-backoff",
		toDuration(mirrorNodeClientBaseBackoffStr),
		"base backoff for mirror node client retries (e.g. 500ms, 1s)")

	mirrorNodeClientTimeoutStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_TIMEOUT", "10s")
	flag.DurationVar(
		&cfg.mirrorNodeClientTimeout,
		"mirror-node-client-retry-timeout",
		toDuration(mirrorNodeClientTimeoutStr),
		"HTTP timeout for mirror node client requests (e.g. 2s, 10s)")
```

**File:** pinger/main.go (L41-49)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}

	// Mark readiness for exec probe (creates /tmp/ready)
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```
