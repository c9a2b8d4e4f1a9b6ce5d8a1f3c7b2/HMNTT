### Title
Rate-Limit Token Leak via Asymmetric Restore on Gas Validation Failure

### Summary
In `ContractController.call()`, `throttleManager.throttle(request)` is called before `validateContractMaxGasLimit(request)`. When gas validation fails, the catch block calls `throttleManager.restore(request.getGas())`, which only restores tokens to the `gasLimitBucket` — it never restores the 1 token consumed from the global `rateLimitBucket`. An unprivileged attacker can craft a flood of requests with `gas > maxGasLimit`, permanently draining the shared rate-limit bucket for all users while their own gas tokens are fully refunded.

### Finding Description

**Exact code path:**

`ContractController.java` lines 40–49:
```java
throttleManager.throttle(request);          // line 40: consumes 1 rateLimitBucket token + scaleGas(gas) gasLimitBucket tokens
validateContractMaxGasLimit(request);       // line 41: throws InvalidParametersException if gas > maxGasLimit
...
} catch (InvalidParametersException e) {
    throttleManager.restore(request.getGas()); // line 48: restores ONLY gasLimitBucket tokens
    throw e;
}
```

`ThrottleManagerImpl.throttle()` (lines 38–42):
```java
if (!rateLimitBucket.tryConsume(1)) { ... }          // consumes 1 rate token
else if (!gasLimitBucket.tryConsume(scaleGas(gas))) { ... }  // consumes gas tokens
```

`ThrottleManagerImpl.restore()` (lines 59–63):
```java
public void restore(long gas) {
    long tokens = throttleProperties.scaleGas(gas);
    if (tokens > 0) {
        gasLimitBucket.addTokens(tokens);   // ONLY gas bucket restored; rateLimitBucket is never touched
    }
}
```

**Root cause:** `restore()` is asymmetric — it only undoes the `gasLimitBucket` deduction, not the `rateLimitBucket` deduction. The failed assumption is that a request rejected by `validateContractMaxGasLimit` should be treated as if it never happened, but the rate-limit token is silently discarded.

**Why existing checks fail:** `ContractCallRequest.gas` carries only `@Min(21_000)` — there is no `@Max` constraint. The configurable `maxGasLimit` (default `15_000_000`) cannot be expressed as a static Bean Validation annotation, so over-limit gas values pass `@Valid` and reach the controller body. The `validateContractMaxGasLimit` check is the only guard, but it fires *after* throttle tokens are already consumed.

### Impact Explanation
The `rateLimitBucket` and `gasLimitBucket` are global singleton Spring beans shared across all callers. Default `requestsPerSecond = 500`. An attacker sending 500+ requests/second with `gas = 15_000_001` (one above the default `maxGasLimit`) will keep the rate bucket empty. Every subsequent legitimate request receives HTTP 429 "Requests per second rate limit exceeded." The attacker's gas tokens are fully restored each time, so the attack costs nothing beyond network bandwidth. This constitutes a complete, sustained denial-of-service against all users of the `/api/v1/contracts/call` endpoint.

### Likelihood Explanation
No authentication, no special privileges, and no on-chain state are required. The endpoint is public. The attacker needs only to know the `maxGasLimit` value (publicly documented default: 15,000,000) and send standard HTTP POST requests. The attack is trivially scriptable, repeatable indefinitely, and self-sustaining because gas tokens are always refunded. A single attacker with modest bandwidth can sustain the condition.

### Recommendation
Restore the `rateLimitBucket` token in addition to the `gasLimitBucket` token when a request is rejected before any real processing occurs. Concretely:

1. Add a `restore(long gas, boolean includeRateToken)` overload (or a separate `restoreAll(long gas)`) to `ThrottleManager` that also calls `rateLimitBucket.addTokens(1)`.
2. Call this full-restore variant from the `InvalidParametersException` catch block in `ContractController.call()`.
3. Alternatively, move `validateContractMaxGasLimit` **before** `throttleManager.throttle(request)` so that over-limit requests are rejected before any tokens are consumed at all — this is the simplest and most robust fix.

### Proof of Concept
```bash
# maxGasLimit default = 15_000_000; send gas one above the limit
# Each request consumes 1 rate token and restores 0 rate tokens

for i in $(seq 1 600); do
  curl -s -o /dev/null -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000001}' &
done
wait

# Now send a legitimate request (gas = 15_000_000):
curl -v -X POST http://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000000}'
# Expected: HTTP 429 "Requests per second rate limit exceeded"
# The attacker's gas tokens were fully restored; only the rate bucket was drained.
```