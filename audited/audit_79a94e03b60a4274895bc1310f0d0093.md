### Title
Global Shared Gas Bucket Allows Unprivileged User to Grief All Legitimate Users via Gas Exhaustion

### Summary
`ThrottleManagerImpl.throttle()` enforces gas-per-second limits using a single shared, global `gasLimitBucket` with no per-user or per-IP isolation. Any unauthenticated caller can send requests at the global rate limit with maximum gas values, draining the shared bucket and causing every subsequent legitimate request to receive `ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED)` for the entire refill window. No authentication or per-source quota prevents this.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.throttle()` at lines 37–48: [1](#0-0) 

The `gasLimitBucket` is a single JVM-wide bean: [2](#0-1) 

Its capacity is `throttleProperties.getGasPerSecond()`, which returns `scaleGas(gasPerSecond)`: [3](#0-2) 

With defaults: `gasPerSecond = 7_500_000_000`, `GAS_SCALE_FACTOR = 10_000`, so effective bucket capacity = **750,000 tokens**, refilled greedily at 750,000 tokens/second. [4](#0-3) 

**Root cause:** `gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))` deducts from one global bucket keyed on nothing — no caller IP, session, or identity. The `rateLimitBucket` (also global, 500 req/sec default) is the only upstream gate, but it is equally global and equally exhaustible by a single attacker. [5](#0-4) 

**Failed assumption:** The design assumes the aggregate request rate (500 req/sec) combined with typical gas values will not exhaust the gas bucket from a single source. This assumption fails because both limits are global with no per-source enforcement.

### Impact Explanation

An attacker sending 500 requests/second (the global `rateLimitBucket` cap), each with gas = 15,000,000 (a common high-gas call), consumes `scaleGas(15_000_000)` = 1,500 tokens per request × 500 = **750,000 tokens/second** — exactly the full bucket capacity. The bucket is drained within one second. All other users receive `ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED)` until the next 1-second refill window. The `restore()` method partially mitigates this only if the attacker's requests complete and gas is refunded, but the depletion window is still sufficient to deny service to legitimate users. [6](#0-5) 

Severity: **Medium** — no economic loss, but complete denial of service to all users of the `/api/v1/contracts/call` endpoint for repeating 1-second windows.

### Likelihood Explanation

- No authentication required; any internet-accessible endpoint is reachable by anyone.
- Attack requires only an HTTP client capable of 500 req/sec — trivially achievable with `ab`, `wrk`, or a simple script.
- Fully repeatable: attacker re-drains the bucket every refill cycle indefinitely.
- No IP-based blocking, no CAPTCHA, no per-source quota exists in this code path. [7](#0-6) 

### Recommendation

1. **Per-source gas quota:** Introduce a per-IP (or per-authenticated-caller) `gasLimitBucket` map so one source cannot exhaust the global pool.
2. **Per-source request rate limit:** Apply the `rateLimitBucket` per-IP before the global check, preventing a single caller from consuming the entire global request allowance.
3. **Cap per-request gas contribution:** Enforce a hard maximum on `request.getGas()` accepted for throttle accounting, independent of what the caller submits.
4. **Integrate with an API gateway or WAF** that enforces per-IP rate limits before requests reach this layer.

### Proof of Concept

```bash
# Drain the global gasLimitBucket in ~1 second
# Assumes default: 500 req/sec global limit, gasPerSecond=7_500_000_000

for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d '{"data":"0x","gas":15000000,"to":"0x0000000000000000000000000000000000000001"}' &
done
wait

# All subsequent legitimate requests within the same 1-second window receive:
# HTTP 429 / ThrottleException: "Gas per second rate limit exceeded."
```

After the burst, any legitimate user calling the same endpoint receives `GAS_PER_SECOND_LIMIT_EXCEEDED` until the bucket refills (~1 second). The attacker repeats the burst each second to maintain the denial of service indefinitely. [8](#0-7)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L18-26)
```java
    private static final long GAS_SCALE_FACTOR = 10_000L;

    @Min(0)
    @Max(100)
    private float gasLimitRefundPercent = 100;

    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L38-47)
```java
    public long getGasPerSecond() {
        return scaleGas(gasPerSecond);
    }

    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```
