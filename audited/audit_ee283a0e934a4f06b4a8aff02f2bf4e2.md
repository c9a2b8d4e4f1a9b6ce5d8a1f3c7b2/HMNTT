### Title
Global Rate Limit Starvation via Single-Client Bucket Exhaustion in `ThrottleManagerImpl.throttle()`

### Summary
`ThrottleManagerImpl.throttle()` enforces rate limiting using two application-scoped singleton `Bucket` instances (`rateLimitBucket` and `gasLimitBucket`) that are shared globally across all clients with no per-source-IP or per-client-identity partitioning. An unprivileged attacker from a single connection can exhaust the entire global token budget, causing all concurrent legitimate users to receive HTTP 429 responses for the duration of the attack.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.throttle()` (lines 37–49) performs two `tryConsume` calls against globally shared singletons:

```java
if (!rateLimitBucket.tryConsume(1)) {           // line 38 — global, shared
    throw new ThrottleException(...);
} else if (!gasLimitBucket.tryConsume(          // line 40 — global, shared
        throttleProperties.scaleGas(request.getGas()))) {
    throw new ThrottleException(...);
}
```

Both buckets are Spring singleton beans instantiated once at startup in `ThrottleConfiguration`:

- `rateLimitBucket`: capacity = `requestsPerSecond` (default **500**), refilled greedily per second
- `gasLimitBucket`: capacity = `scaleGas(gasPerSecond)` = `scaleGas(7_500_000_000)` = **750,000** tokens, refilled per second

**Root cause — failed assumption:**
The design assumes the global limit is sufficient to protect the service, implicitly assuming no single client will consume a disproportionate share. There is no per-client partitioning anywhere in the throttle path.

**Why existing checks are insufficient:**

- `RequestFilter` (lines 39–58 of `RequestFilter.java`) can match on `FROM`, `TO`, `DATA`, `GAS`, `BLOCK`, `VALUE`, `ESTIMATE` — but **not on source IP**. An attacker can rotate the `from` field freely (it is a user-supplied string, not authenticated).
- The `RequestProperties.THROTTLE` action (lines 70–74 of `ThrottleManagerImpl.java`) applies a secondary bucket, but it is also a global singleton per filter rule, not per client.
- `ContractCallRequest` carries no source IP field; the HTTP layer IP is never passed into `throttle()`.
- No external IP-based middleware (e.g., Spring Security, servlet filter) is wired into the web3 throttle path.

**Exploit flow:**

1. Attacker opens a single HTTP connection to the web3 endpoint (e.g., `POST /api/v1/contracts/call`).
2. Attacker sends requests at ≥500 req/s (trivially achievable with any HTTP benchmarking tool).
3. Each request calls `rateLimitBucket.tryConsume(1)`, draining all 500 tokens within the first second.
4. All subsequent requests from any other client hit `!rateLimitBucket.tryConsume(1) == true` and receive `ThrottleException` → HTTP 429.
5. The bucket refills at 500 tokens/s; the attacker immediately re-drains it. The attack is self-sustaining.

**Gas bucket variant (single-request exhaustion):**

A single request with `gas = 7_500_000_000` (the default `gasPerSecond`) calls `gasLimitBucket.tryConsume(750_000)`, consuming the entire gas budget in one shot. All other users' gas-consuming requests fail for up to 1 second per such request.

### Impact Explanation

All legitimate users sharing the same deployment are denied service (HTTP 429) for the duration of the attack. The `rateLimitBucket` starvation attack is continuous and self-sustaining with no recovery window. The `gasLimitBucket` variant can be triggered with a single high-gas request. This constitutes a complete application-layer DoS against the web3 contract call endpoint, requiring zero authentication or special privileges.

### Likelihood Explanation

The attack requires only the ability to send HTTP POST requests to the public endpoint — no credentials, no special knowledge, no on-chain assets. Any script kiddie with `curl`, `wrk`, or `ab` can execute it. The attack is repeatable indefinitely and is not self-limiting (the attacker is not penalized for exhausting the bucket; they simply receive 429 themselves after the bucket is empty, but they can immediately retry). Likelihood is **high**.

### Recommendation

Replace the single global `Bucket` instances with per-client buckets keyed by source IP (or authenticated identity). Bucket4j supports this via `BucketProxyManager` / `CaffeineProxyManager` with a `KeyedBucketProxy`. Concretely:

1. Inject a `CaffeineProxyManager<String>` (or equivalent) instead of a bare `Bucket`.
2. In `throttle()`, extract the client IP from the `HttpServletRequest` (available via `RequestContextHolder` or by passing it into the method) and call `proxyManager.getProxy(clientIp).tryConsume(1)`.
3. Apply a per-client limit (e.g., 50 req/s per IP) in addition to the global cap, so no single client can starve others.
4. Consider also rate-limiting by `X-Forwarded-For` with trusted-proxy validation to handle reverse-proxy deployments.

### Proof of Concept

```bash
# Exhaust the global rateLimitBucket (500 req/s default) from a single client
wrk -t4 -c50 -d30s -s post.lua http://<host>/api/v1/contracts/call

# post.lua:
# wrk.method = "POST"
# wrk.body   = '{"to":"0x0000000000000000000000000000000000000001","gas":21000}'
# wrk.headers["Content-Type"] = "application/json"
```

Expected result: within the first second, all tokens in `rateLimitBucket` are consumed. A concurrent legitimate client sending even a single request receives HTTP 429 `"Requests per second rate limit exceeded"` for the duration of the attack.

**Gas-bucket single-shot exhaustion:**
```bash
curl -X POST http://<host>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":7500000000}'
```

This single request drains all 750,000 scaled gas tokens, blocking all other gas-consuming calls for up to 1 second. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L39-48)
```java
    enum FilterField {
        BLOCK(ContractCallRequest::getBlock),
        DATA(ContractCallRequest::getData),
        ESTIMATE(ContractCallRequest::isEstimate),
        FROM(ContractCallRequest::getFrom),
        GAS(ContractCallRequest::getGas),
        TO(ContractCallRequest::getTo),
        VALUE(ContractCallRequest::getValue);

        private final Function<ContractCallRequest, Object> extractor;
```
