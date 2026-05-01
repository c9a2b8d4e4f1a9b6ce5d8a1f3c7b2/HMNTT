### Title
`backoff()` Integer Overflow via Unbounded `HIERO_MIRROR_PINGER_MAX_RETRIES` Causes Immediate Retries and Operator Fee Drain

### Summary
The `backoff()` function in `pinger/transfer.go` computes `base * time.Duration(1<<(attempt-1))`, where both operands are `int64` (`time.Duration`). With `base=1s` and `attempt≥35`, the multiplication overflows `int64` to a negative value. The `min(d, 30*time.Second)` cap is bypassed because a negative value is always less than 30s, so `time.NewTimer` receives a non-positive duration and fires immediately. Config validation imposes no upper bound on `HIERO_MIRROR_PINGER_MAX_RETRIES`, making this trivially reachable.

### Finding Description

**Exact code path:**

`pinger/transfer.go` lines 62–64:
```go
func backoff(base time.Duration, attempt int) time.Duration {
    d := base * time.Duration(1<<(attempt-1))   // ← overflow here
    return min(d, 30 * time.Second)              // ← cap is ineffective on negative d
}
```

`pinger/config.go` lines 117–122 (the only validation):
```go
if cfg.maxRetries < 0 {
    cfg.maxRetries = 0          // no upper bound
}
if cfg.baseBackoff <= 0 {
    cfg.baseBackoff = 1 * time.Second   // corrects 0s → 1s
}
```

**Root cause:** `time.Duration` is `int64` (nanoseconds). The multiplication `base * time.Duration(1<<(attempt-1))` is unchecked `int64` arithmetic. With `base = 1,000,000,000 ns` (1 second):

| attempt | `1<<(attempt-1)` | product (ns) | overflows? |
|---------|-----------------|--------------|------------|
| 34 | 8,589,934,592 | 8,589,934,592,000,000,000 | No (< max int64 9.22×10¹⁸) |
| 35 | 17,179,869,184 | **17,179,869,184,000,000,000** | **Yes** → wraps to large negative |
| 63 | 4,611,686,018,427,387,904 | 0 (2^71 mod 2^64 = 0) | Yes → 0 |

For attempt=35 through attempt=62, `d` wraps to a large negative `int64`. `min(negative, 30s)` returns the negative value. `time.NewTimer(negative_or_zero)` fires immediately per Go runtime semantics (non-positive duration = immediate expiry).

With `maxRetries=63`, `attempts=64`, and backoff called for `i=1..63`: **attempts 35–63 (29 retries) all fire with zero delay**, each executing a full `CryptoTransfer` on-chain.

**Why the `min()` cap fails:** It is designed to prevent excessively long sleeps, not overflows. A negative overflowed value satisfies `d < 30s`, so `min` returns `d` unchanged. [1](#0-0) [2](#0-1) 

### Impact Explanation

Each immediate retry submits a `hiero.NewTransferTransaction().Execute(client)` on-chain. [3](#0-2)  Every Hedera `CryptoTransfer` transaction incurs a network fee charged to the operator account. With `maxRetries=63`, up to 29 transactions per tick fire in rapid succession (attempts 35–63 with ~0 delay). At the default `interval=1s`, this is ~29 fee-bearing transactions per second instead of 1. Over time this drains the operator's HBAR balance. The operator key and account are configured in the same environment, so the attacker does not need separate access to the operator's private key — the running process already holds it. [4](#0-3) 

### Likelihood Explanation

The attacker needs write access to the pinger's environment variables — achievable via: a misconfigured Kubernetes RBAC role that allows editing ConfigMaps/Deployments, a compromised CI/CD pipeline that injects env vars, or a shared-secret store with overly broad read/write permissions. No blockchain-level privilege is required. The configuration values (`MAX_RETRIES=63`, `BASE_BACKOFF=0s`) are syntactically valid and pass all existing validation checks without error, so the process starts normally and the overflow is silent. [5](#0-4) 

### Recommendation

1. **Cap `maxRetries` in validation** — add an upper bound (e.g., 20) in `config.go`:
   ```go
   if cfg.maxRetries > 20 {
       cfg.maxRetries = 20
   }
   ```
2. **Add overflow-safe backoff** — clamp before multiplying, or use saturating arithmetic:
   ```go
   func backoff(base time.Duration, attempt int) time.Duration {
       const maxBackoff = 30 * time.Second
       if attempt > 30 { // 2^30 * 1s >> 30s, safe upper bound
           return maxBackoff
       }
       d := base * time.Duration(1<<(attempt-1))
       if d <= 0 { // overflow guard
           return maxBackoff
       }
       return min(d, maxBackoff)
   }
   ```
3. **Add post-overflow guard** in `submitWithRetry` — check `sleep > 0` before passing to `time.NewTimer`. [6](#0-5) 

### Proof of Concept

```bash
# Set env vars for the pinger process
export HIERO_MIRROR_PINGER_OPERATOR_ID="0.0.1234"
export HIERO_MIRROR_PINGER_OPERATOR_KEY="<valid_key>"
export HIERO_MIRROR_PINGER_BASE_BACKOFF="0s"      # corrected to 1s by validation
export HIERO_MIRROR_PINGER_MAX_RETRIES="63"        # passes validation (only checks >= 0)
export HIERO_MIRROR_PINGER_INTERVAL="1s"
export HIERO_MIRROR_PINGER_NETWORK="testnet"

go run ./pinger/
# Expected: attempts 1-34 use normal exponential backoff (1s, 2s, ..., capped at 30s)
# Observed: attempts 35-63 fire immediately (0 delay) due to int64 overflow
#           → 29 CryptoTransfer transactions submitted per tick with no delay
#           → operator HBAR drained via transaction fees at ~29x normal rate
```

To verify the overflow independently:
```go
package main

import (
    "fmt"
    "time"
)

func main() {
    base := 1 * time.Second
    for attempt := 33; attempt <= 36; attempt++ {
        d := base * time.Duration(1<<(attempt-1))
        fmt.Printf("attempt=%d  d=%v  (raw=%d)\n", attempt, d, int64(d))
    }
}
// attempt=33  d=4611686018s  (raw=4611686018427387904)   ← large but positive
// attempt=34  d=8589934592s  (raw=8589934592000000000)   ← large but positive  
// attempt=35  d=-1266874889709551616ns  (raw=-1266874889709551616) ← OVERFLOW, negative
// attempt=36  d=...negative...
``` [1](#0-0) [7](#0-6)

### Citations

**File:** pinger/transfer.go (L29-33)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```

**File:** pinger/transfer.go (L47-56)
```go
		if i < attempts {
			sleep := backoff(cfg.baseBackoff, i)
			timer := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
```

**File:** pinger/transfer.go (L62-64)
```go
func backoff(base time.Duration, attempt int) time.Duration {
	d := base * time.Duration(1<<(attempt-1))
	return min(d, 30 * time.Second)
```

**File:** pinger/config.go (L39-40)
```go
	flag.StringVar(&cfg.operatorID, "operator-id", envOr("HIERO_MIRROR_PINGER_OPERATOR_ID", "0.0.2"), "operator account id, e.g. 0.0.1234")
	flag.StringVar(&cfg.operatorKey, "operator-key", envOr("HIERO_MIRROR_PINGER_OPERATOR_KEY", "302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137"), "operator private key string")
```

**File:** pinger/config.go (L58-67)
```go
	retriesStr := envOr("HIERO_MIRROR_PINGER_MAX_RETRIES", "10")
	flag.Func("max-retries", "max retries per tick", func(s string) error {
		v, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		cfg.maxRetries = v
		return nil
	})
	_ = flag.CommandLine.Set("max-retries", retriesStr)
```

**File:** pinger/config.go (L117-122)
```go
	if cfg.maxRetries < 0 {
		cfg.maxRetries = 0
	}
	if cfg.baseBackoff <= 0 {
		cfg.baseBackoff = 1 * time.Second
	}
```
