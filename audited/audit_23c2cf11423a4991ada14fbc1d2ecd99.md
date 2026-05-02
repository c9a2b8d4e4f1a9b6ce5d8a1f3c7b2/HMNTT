### Title
Global Shared Rate-Limit Bucket Allows Single Unprivileged Client to Exhaust All Request Tokens (Application-Layer DoS)

### Summary
`ThrottleManagerImpl.throttle()` enforces a single process-wide `rateLimitBucket` with no per-IP or per-user partitioning. Any unauthenticated caller can saturate the entire token pool at the configured `requestsPerSecond` ceiling (default 500 req/s), causing every subsequent request from every other client to receive HTTP 429 until the bucket refills one second later. This is trivially repeatable and requires zero privileges.

### Finding Description
**Code path:**

- `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java` lines 24–32: a single `Bucket` bean named `rateLimitBucket` is created with capacity = `throttleProperties.getRequestsPerSecond()` (default **500**) and a greedy refill of the same value every 1 second.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java` lines 37–42: every call to `throttle()` does `rateLimitBucket.tryConsume(1)`. If the bucket is empty the method throws `ThrottleException("Requests per second rate limit exceeded")`, which maps to HTTP 429.

There is no map, cache, or secondary bucket keyed on remote IP, API key, session, or any other per-caller identity. The `LoggingFilter` records `request.getRemoteAddr()` for observability only; it plays no role in throttling decisions.

The optional `RequestProperties` filter chain (lines 44–48 of `ThrottleManagerImpl`) can add per-pattern sub-buckets, but:
- it is **not configured by default** (`request = List.of()`);
- even when configured, it is evaluated **after** the global bucket has already been consumed, so it cannot compensate for global exhaustion.

**Root cause:** The design assumes the global bucket will be shared fairly across many independent callers. That assumption fails when a single caller issues requests at or above the global ceiling.

### Impact Explanation
A single attacker sending ≥ 500 HTTP requests per second (trivially achievable with any HTTP benchmarking tool or a small script) drains the global token pool. For the remainder of that one-second window every other client—regardless of their own request rate—receives HTTP 429. The attack is stateless, requires no authentication, and can be sustained indefinitely. The effective availability of the `/api/v1/contracts/call` (and opcode) endpoints drops to zero for all legitimate users while the attacker is active.

### Likelihood Explanation
The precondition is zero: no account, no API key, no special network position. The attacker needs only a single machine capable of ~500 HTTP requests per second, which is well within reach of commodity hardware or a small cloud VM. The attack is fully repeatable every second and leaves no persistent state to clean up. Detection is possible via logs, but the damage (service unavailability) occurs before any mitigation can be applied at the application layer.

### Recommendation
Replace the single global bucket with a per-caller bucket map (e.g., keyed on `X-Forwarded-For` / `RemoteAddr`). Bucket4j supports `ProxyManager` backed by Caffeine or Redis for exactly this pattern. A two-tier approach works well: enforce a per-IP limit (e.g., 50 req/s) **and** retain the global ceiling as a backstop. If infrastructure-level rate limiting (API gateway, WAF) is already in place in all deployments, document that dependency explicitly and add a startup warning when no such header is present.

### Proof of Concept
```
# 1. Start the mirror-node web3 service with default config (requestsPerSecond=500).
# 2. From attacker machine, saturate the global bucket:
ab -n 100000 -c 600 http://<target>/api/v1/contracts/call \
   -p payload.json -T application/json

# 3. Simultaneously, from a separate legitimate client:
curl http://<target>/api/v1/contracts/call -d @legit.json

# Expected result for legitimate client while attack is running:
# HTTP/1.1 429 Too Many Requests
# {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}

# The attacker requires no credentials, no special headers, and no prior knowledge
# of the system beyond the public endpoint URL.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
