### Title
Rate-Limit Token Leaked on Gas-Check Failure Enables Amplified DoS

### Summary
In `ThrottleManagerImpl.throttle()`, a rate-limit token is consumed from `rateLimitBucket` before the gas check is attempted. When `gasLimitBucket.tryConsume()` fails, the already-consumed rate-limit token is silently discarded — there is no rollback and `restore()` only refunds gas tokens. An unprivileged attacker who first exhausts the gas bucket can then flood the endpoint, draining the rate-limit bucket with zero gas consumed per request, starving legitimate users of both throttle dimensions simultaneously.

### Finding Description
**Exact code path:** `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, `throttle()`, lines 38–42.

```java
if (!rateLimitBucket.tryConsume(1)) {               // line 38 — token consumed here
    throw new ThrottleException(...);
} else if (!gasLimitBucket.tryConsume(...)) {        // line 40 — may fail
    throw new ThrottleException(...);                // line 41 — rate token NOT restored
}
```

**Root cause:** The two `tryConsume` calls are sequential and non-atomic. When line 40 fails, execution jumps to line 41 and throws. The rate-limit token consumed on line 38 is never returned. The `restore()` method (lines 59–64) only calls `gasLimitBucket.addTokens()` — there is no corresponding `rateLimitBucket.addTokens()` path anywhere in the codebase.

**Exploit flow:**

1. **Phase 1 – exhaust gas bucket.** Default config: `gasPerSecond = 7,500,000,000` → scaled capacity = `750,000` tokens; max gas per request = `15,000,000` → scaled cost = `1,500` tokens. The attacker sends 500 requests (one full second of rate-limit budget) each with `gas = 15,000,000`. This consumes `500 × 1,500 = 750,000` gas tokens — exactly the full gas bucket — while also consuming all 500 rate-limit tokens for that second.

2. **Phase 2 – exploit the TOCTOU window.** In the next second both buckets refill. The attacker again sends 500 requests with `gas = 15,000,000`. For each request: rate-limit token is consumed (line 38 succeeds), gas check fails (line 40 fails, bucket empty after ~500 requests), `ThrottleException` is thrown, rate-limit token is gone. The attacker has now drained the rate-limit bucket entirely with no gas processed.

3. **Result.** Legitimate users attempting requests in the same second find both the gas bucket and the rate-limit bucket empty. They receive `ThrottleException` on the rate-limit check (line 38) even though zero gas was consumed on their behalf. The cycle repeats every second as long as the attacker keeps flooding.

**Why existing checks are insufficient:**
- The `rateLimitBucket` is built without `SynchronizationStrategy.SYNCHRONIZED` (lines 24–32 of `ThrottleConfiguration.java`), so concurrent threads each independently consume a token before the gas check.
- `restore()` (lines 59–64) has no awareness of the rate-limit bucket; it cannot compensate.
- There is no try/finally or compensating `addTokens` call on `rateLimitBucket` anywhere in the call chain.

### Impact Explanation
A single unauthenticated attacker can sustain a complete denial-of-service against all contract-call endpoints. By keeping the gas bucket perpetually empty, every incoming request — attacker's or legitimate — consumes a rate-limit token and is rejected. Legitimate users receive HTTP 429 errors continuously. The attack requires no credentials, no special knowledge, and no on-chain funds.

### Likelihood Explanation
The precondition (exhausting the gas bucket) is achievable by any caller in one second using the default configuration. The exploit is trivially repeatable every refill cycle (~1 second). No authentication, no privileged access, and no special tooling beyond a standard HTTP client are required. The attack is fully automatable and can be sustained indefinitely.

### Recommendation
Restore the rate-limit token when the gas check fails. The simplest correct fix is to reverse the check order (check gas first, then rate) or to explicitly return the token on gas failure:

```java
@Override
public void throttle(ContractCallRequest request) {
    long scaledGas = throttleProperties.scaleGas(request.getGas());
    // Check gas first — no side-effect if it fails
    if (scaledGas > 0 && !gasLimitBucket.tryConsume(scaledGas)) {
        throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
    }
    // Only consume rate token after gas is confirmed available
    if (!rateLimitBucket.tryConsume(1)) {
        if (scaledGas > 0) gasLimitBucket.addTokens(scaledGas); // rollback
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
    ...
}
```

Alternatively, use bucket4j's `tryConsumeAndReturnRemaining` with a probe before committing, or wrap both checks in a single synchronized block that rolls back on partial failure.

### Proof of Concept
```
# Default config: requestsPerSecond=500, gasPerSecond=7_500_000_000, maxGasLimit=15_000_000

# Step 1: exhaust gas bucket in 1 second (500 requests × gas=15000000)
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"0x","gas":15000000,"to":"0x0000000000000000000000000000000000000001"}' &
done
wait

# Step 2: in the next second, flood again — rate-limit tokens consumed, gas check fails
# Legitimate users now receive 429 on BOTH rate-limit and gas-limit checks
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"0x","gas":15000000,"to":"0x0000000000000000000000000000000000000001"}' &
done
wait

# Observe: all 500 rate-limit tokens consumed, gas bucket empty,
# legitimate requests receive ThrottleException on rate-limit check
# with zero gas processed.
```