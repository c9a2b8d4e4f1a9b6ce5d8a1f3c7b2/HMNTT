### Title
Unguarded Bit-Shift Overflow in `backoff()` Eliminates Retry Delays When `HIERO_MIRROR_PINGER_MAX_RETRIES >= 64`

### Summary
The `backoff()` function in `pinger/transfer.go` computes `1<<(attempt-1)` using a runtime shift on a signed `int`, which overflows to `math.MinInt64` (or zero) when `attempt-1 >= 63`. The `min(d, 30*time.Second)` cap only bounds the maximum, not the minimum, so a zero or negative result passes through unchecked. `time.NewTimer` treats any duration `<= 0` as an immediate fire, eliminating all inter-retry delays and enabling rapid-fire HBAR transfer submissions that drain transaction fees.

### Finding Description

**Exact code location:** `pinger/transfer.go`, `backoff()`, lines 62–64; called from `submitWithRetry()` line 48.

```go
// pinger/transfer.go:62-64
func backoff(base time.Duration, attempt int) time.Duration {
    d := base * time.Duration(1<<(attempt-1))   // ← unguarded shift
    return min(d, 30 * time.Second)              // ← caps max only, not min
}
```

**Root cause:** In Go, `1` in `1<<(attempt-1)` is an untyped constant that resolves to `int` (64-bit on amd64) because the shift amount is a runtime variable. Integer overflow is well-defined in Go (two's-complement wrap-around):

- `attempt-1 = 63` → `1<<63 = math.MinInt64` (negative). For `base = 2 s = 2,000,000,000 ns`: `2,000,000,000 × math.MinInt64 mod 2⁶⁴ = 0` (since `2e9` is even, `even × 2⁶³ mod 2⁶⁴ = 0`). Result: `d = 0`.
- `attempt-1 >= 64` → Go left-shift by ≥ word-size yields `0`. Result: `d = 0`.

`min(0, 30*time.Second)` returns `0`. `time.NewTimer(0)` fires immediately per Go runtime semantics.

**Config validation gap:** `pinger/config.go` lines 117–119 only enforce a lower bound:

```go
if cfg.maxRetries < 0 {
    cfg.maxRetries = 0
}
```

No upper bound is enforced. Setting `HIERO_MIRROR_PINGER_MAX_RETRIES=64` is accepted without error.

**Exploit flow:**
1. Attacker sets `HIERO_MIRROR_PINGER_MAX_RETRIES=64` (or higher) in the deployment environment.
2. `submitWithRetry` sets `attempts = 65` and loops `i = 1..65`.
3. For `i = 64`: `backoff(2s, 64)` → `1<<63 = math.MinInt64` → `d = 0` → `time.NewTimer(0)` fires instantly.
4. For `i >= 65` (if `maxRetries > 64`): `1<<64 = 0` → `d = 0` → same result.
5. All retries from attempt 64 onward execute with zero delay, back-to-back.

With `maxRetries = 1000`, attempts 64–999 (936 iterations) fire with no inter-retry pause, each submitting a signed `CryptoTransfer` transaction to the Hedera network and paying a transaction fee.

### Impact Explanation
Each rapid-fire retry in `submitWithRetry` calls `cryptoTransfer.Execute(client)` (line 33), which submits a real signed transaction to the Hedera consensus network and incurs a transaction fee from the operator account. With zero backoff across hundreds of retries per tick, and the tick interval still firing every second (line 54 of `main.go`), the operator's HBAR balance is drained at the maximum rate the network accepts transactions. The `amountTinybar` transferred per attempt (default 10,000 tinybar) compounds the loss. This is a direct, irreversible loss of funds from the operator account.

### Likelihood Explanation
The precondition is the ability to set the `HIERO_MIRROR_PINGER_MAX_RETRIES` environment variable. In Kubernetes deployments this requires write access to the Deployment/ConfigMap — achievable by a malicious insider, a compromised CI/CD pipeline, or misconfigured RBAC. The pinger is a long-running service designed to run unattended; the misconfiguration may go unnoticed until the operator account is drained. No cryptographic material or network-level access is required beyond deployment configuration.

### Recommendation
Apply two independent fixes:

1. **Cap `maxRetries` at a safe upper bound in `loadConfig()`** (`pinger/config.go`, after line 119):
   ```go
   const maxAllowedRetries = 62  // keeps attempt-1 <= 61, shift stays safe
   if cfg.maxRetries > maxAllowedRetries {
       cfg.maxRetries = maxAllowedRetries
   }
   ```

2. **Guard against overflow in `backoff()` itself** (`pinger/transfer.go`, lines 62–64):
   ```go
   func backoff(base time.Duration, attempt int) time.Duration {
       if attempt > 62 {
           attempt = 62
       }
       d := base * time.Duration(1<<uint(attempt-1))
       if d <= 0 {
           d = 30 * time.Second
       }
       return min(d, 30*time.Second)
   }
   ```
   Using `uint` for the shift operand also makes the overflow semantics explicit and avoids signed-integer UB in future Go versions.

### Proof of Concept

```bash
# 1. Deploy pinger with a high retry count and a base backoff
export HIERO_MIRROR_PINGER_MAX_RETRIES=128
export HIERO_MIRROR_PINGER_BASE_BACKOFF=2s
export HIERO_MIRROR_PINGER_OPERATOR_ID=<operator>
export HIERO_MIRROR_PINGER_OPERATOR_KEY=<key>
export HIERO_MIRROR_PINGER_TO_ACCOUNT_ID=<destination>

# 2. Run the pinger against a network where transfers will fail
#    (e.g., wrong destination, or deliberately throttled)
go run ./pinger/...

# 3. Observe in logs: attempts 1-63 show increasing delays (1s, 2s, 4s...capped at 30s)
#    Attempts 64-128 show zero delay between log lines — all fire instantly
#    Each attempt still submits a signed transaction and pays a fee

# 4. Reproduce the arithmetic in Go:
# attempt=64: 1<<63 = -9223372036854775808 (math.MinInt64)
# time.Duration(math.MinInt64) = -9223372036854775808
# 2_000_000_000 * (-9223372036854775808) mod 2^64 = 0
# min(0, 30s) = 0  → timer fires immediately

# attempt=65: 1<<64 = 0 (Go: shift >= word size → 0)
# 2_000_000_000 * 0 = 0 → timer fires immediately
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** pinger/config.go (L117-119)
```go
	if cfg.maxRetries < 0 {
		cfg.maxRetries = 0
	}
```
