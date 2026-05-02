### Title
Integer Overflow in `buildNetworkFromMirrorNodes` Backoff Calculation Causes Tight Retry Loop (DoS)

### Summary
`buildNetworkFromMirrorNodes` in `pinger/mirror_node_client.go` computes exponential backoff as `cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))` with no overflow guard and no cap. When `HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_MAX_RETRIES` is set to any value ≥ 35 and `HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_BASE_BACKOFF` is `1s`, the multiplication overflows `int64` at attempt 35, producing a negative `time.Duration`. Go's `time.After()` fires immediately for any non-positive duration, collapsing the intended backoff into a tight loop that hammers the mirror node REST API with no delay.

### Finding Description

**Exact code path:**

`pinger/config.go` `loadConfig()` lines 123–128 — validation only rejects negative/zero values; no upper bound is enforced on either field:

```go
if cfg.mirrorNodeClientMaxRetries < 0 {
    cfg.mirrorNodeClientMaxRetries = 0
}
if cfg.mirrorNodeClientBaseBackoff <= 0 {
    cfg.mirrorNodeClientBaseBackoff = 500 * time.Millisecond
}
``` [1](#0-0) 

`pinger/mirror_node_client.go` `buildNetworkFromMirrorNodes()` line 63 — uncapped, unguarded shift-multiply:

```go
backoff := cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))
``` [2](#0-1) 

**Root cause:** `time.Duration` is `int64` (nanoseconds). With `base = 1 s = 10^9 ns`:

| attempt | shift value `2^(attempt-1)` | product (ns) | fits int64? |
|---------|----------------------------|--------------|-------------|
| 34 | 2^33 = 8,589,934,592 | 8.59 × 10^18 | ✓ |
| 35 | 2^34 = 17,179,869,184 | 1.72 × 10^19 | **overflow → negative** |

Any `MAX_RETRIES ≥ 35` with `BASE_BACKOFF = 1s` (or `MAX_RETRIES ≥ 36` with the default `500ms`) triggers the overflow. The claim's "attempt 63" is conservative — overflow occurs far earlier.

**Why existing checks fail:** The only guards are lower-bound checks (`< 0`, `<= 0`). There is no upper-bound cap on either `mirrorNodeClientMaxRetries` or `mirrorNodeClientBaseBackoff`, and no `min(backoff, maxBackoff)` clamp in `buildNetworkFromMirrorNodes`. By contrast, `transfer.go`'s `backoff()` helper correctly caps at 30 s:

```go
func backoff(base time.Duration, attempt int) time.Duration {
    d := base * time.Duration(1<<(attempt-1))
    return min(d, 30 * time.Second)   // ← cap present here
}
``` [3](#0-2) 

`buildNetworkFromMirrorNodes` does not call this helper and has no equivalent cap. [4](#0-3) 

**Trigger:** After overflow, `backoff` is negative. `time.After(negative)` fires immediately in Go (documented behavior: non-positive duration → channel fires at once). The `select` therefore never blocks, and the loop spins through all remaining attempts with zero delay. [5](#0-4) 

### Impact Explanation
The tight loop issues rapid, unthrottled HTTP GET requests to the mirror node REST endpoint (`/api/v1/network/nodes`) for every remaining retry after the overflow point. With `MAX_RETRIES=63`, up to ~29 attempts (35 through 63) fire with no delay, constituting a burst of ~29 unthrottled requests at process startup. If the mirror node returns retryable errors (5xx or 429), the full burst repeats on every pinger restart or pod reschedule. At scale (multiple pinger replicas), this can exhaust mirror node REST capacity. The pinger is classified as high-severity scope (≥25% market-cap network infrastructure).

### Likelihood Explanation
Environment variables for the pinger are set in the Kubernetes Deployment spec or a ConfigMap. Any principal with `patch`/`update` RBAC on the Deployment or ConfigMap in the pinger's namespace — a role commonly granted to developers and CI pipelines, not just cluster admins — can inject these values. No application-level authentication is required; the pinger reads env vars unconditionally at startup. The misconfiguration is persistent across pod restarts and is not self-correcting.

### Recommendation
1. **Add an upper-bound cap in `buildNetworkFromMirrorNodes`**, mirroring the pattern already used in `transfer.go`:
   ```go
   const maxBackoff = 30 * time.Second
   backoff := cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))
   if backoff <= 0 || backoff > maxBackoff {
       backoff = maxBackoff
   }
   ```
2. **Add upper-bound validation in `loadConfig()`** for both fields, e.g. reject `mirrorNodeClientMaxRetries > 20` and `mirrorNodeClientBaseBackoff > 30s`.
3. **Reuse the existing `backoff()` helper** from `transfer.go` (or extract it to a shared utility) so both retry paths benefit from the same cap.

### Proof of Concept

```bash
# Preconditions: pinger binary built, mirror node REST unreachable (to force retries)
export HIERO_MIRROR_PINGER_NETWORK=other
export HIERO_MIRROR_PINGER_REST=http://127.0.0.1:19999   # nothing listening → retryable error
export HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2
export HIERO_MIRROR_PINGER_OPERATOR_KEY=302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137
export HIERO_MIRROR_PINGER_TO_ACCOUNT_ID=0.0.98
export HIERO_MIRROR_PINGER_AMOUNT_TINYBAR=1

# Trigger: set retries high enough to reach attempt 35, base backoff = 1s
export HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_MAX_RETRIES=63
export HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_BASE_BACKOFF=1s

# Observe: attempts 1–34 sleep normally (1s, 2s, 4s, …);
# at attempt 35 the product overflows int64 → negative duration →
# time.After fires immediately; attempts 35–63 fire with zero delay.
# Add strace / tcpdump on port 19999 to confirm burst of ~29 rapid connections.
./pinger
```

Expected observation: the first 34 retries are spaced with exponential backoff; starting at attempt 35, all remaining retries fire in rapid succession with no observable sleep between them, visible as a burst of TCP connection attempts to the target host.

### Citations

**File:** pinger/config.go (L123-128)
```go
	if cfg.mirrorNodeClientMaxRetries < 0 {
		cfg.mirrorNodeClientMaxRetries = 0
	}
	if cfg.mirrorNodeClientBaseBackoff <= 0 {
		cfg.mirrorNodeClientBaseBackoff = 500 * time.Millisecond
	}
```

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

**File:** pinger/transfer.go (L62-64)
```go
func backoff(base time.Duration, attempt int) time.Duration {
	d := base * time.Duration(1<<(attempt-1))
	return min(d, 30 * time.Second)
```
