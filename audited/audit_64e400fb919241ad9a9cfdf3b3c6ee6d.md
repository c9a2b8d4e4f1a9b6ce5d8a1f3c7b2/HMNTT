### Title
In-Memory Rate Limit Bucket Bypass via Multi-Instance Deployment (Per-Instance Token Multiplication)

### Summary
The `rateLimitBucket()` bean in `ThrottleConfiguration.java` creates a purely local, JVM-heap-resident bucket4j token bucket with no distributed backend. In any multi-replica deployment, each instance independently holds the full configured token capacity, so an unprivileged attacker can drive aggregate throughput to N × `requestsPerSecond` (default 500 RPS × N instances) by simply sending requests through the load balancer, with no throttle ever firing on any individual node.

### Finding Description
**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, `rateLimitBucket()`, lines 24–32:

```java
@Bean(name = RATE_LIMIT_BUCKET)
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond();
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)
            .refillGreedy(rateLimit, Duration.ofSeconds(1))
            .build();
    return Bucket.builder().addLimit(limit).build();  // local JVM bucket, no distributed backend
}
```

`Bucket.builder().addLimit(limit).build()` constructs a `LocalBucket` backed entirely by JVM heap. There is no `ProxyManager`, no Redis/Hazelcast/JDBC distributed backend, and no cross-instance coordination anywhere in the web3 module (confirmed by absence of any `bucket4j-redis`, `bucket4j-hazelcast`, or `ProxyManager` usage).

The enforcement point in `ThrottleManagerImpl.throttle()` (line 38) calls `rateLimitBucket.tryConsume(1)` against this local state only:

```java
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
}
```

**Root cause / failed assumption:** The implementation assumes a single-instance deployment. The rate limit is intended to be a global cap, but each replica enforces only its own independent bucket. No distributed token store is used.

**Contrast with `gasLimitBucket`:** The gas bucket uses `SynchronizationStrategy.SYNCHRONIZED` (line 42) for intra-JVM thread safety, but this is still a local bucket — it does not coordinate across instances. The `rateLimitBucket` and `opcodeRateLimitBucket` lack even that.

**Exploit flow:**
1. Attacker sends requests at rate R through the load balancer (round-robin or least-connections).
2. With N instances, each instance receives approximately R/N requests per second.
3. Each instance's local bucket allows up to 500 RPS independently.
4. As long as R/N ≤ 500, no instance ever fires `ThrottleException`.
5. Total aggregate throughput reaching the backend: R = N × 500 RPS.

### Impact Explanation
With the default `requestsPerSecond = 500` and a standard 2-replica HA deployment, an attacker can sustain 1,000 RPS (100% above the intended cap) without triggering any throttle response. Each request triggers EVM execution, database queries, and gas accounting — all CPU/IO-intensive operations. This directly increases node resource consumption well above the 30% threshold stated in scope. With 3 replicas the multiplier is 3×, and so on. The `gasLimitBucket` is similarly affected, allowing N × `gasPerSecond` aggregate gas processing. The `opcodeRateLimitBucket` (default 1 RPS, intended to protect a heavy endpoint) becomes N RPS, which is especially dangerous given the documented note that "this endpoint is heavy and the value needs to be low."

### Likelihood Explanation
No privileges, credentials, or special knowledge are required. Any external user can send HTTP POST requests to `/api/v1/contracts/call`. The attacker does not need to discover individual instance IPs — a standard load-balanced endpoint suffices, since the load balancer itself distributes the requests across instances. This is trivially repeatable and scriptable with any HTTP benchmarking tool (e.g., `wrk`, `hey`, `ab`). Production Kubernetes deployments of mirror nodes routinely run 2–5 replicas for availability, making this condition the norm rather than the exception.

### Recommendation
Replace the local `Bucket.builder()` construction with a distributed bucket4j backend shared across all instances. The bucket4j library supports Redis (`bucket4j-redis`), Hazelcast, and JDBC backends via `ProxyManager`. For example, using the Redis integration:

```java
// Use a shared Redis-backed ProxyManager instead of Bucket.builder()
BucketConfiguration config = BucketConfiguration.builder()
    .addLimit(Bandwidth.builder().capacity(rateLimit).refillGreedy(rateLimit, Duration.ofSeconds(1)).build())
    .build();
return proxyManager.builder().build(RATE_LIMIT_KEY, () -> config);
```

Alternatively, if a distributed store is not feasible, divide the configured limit by the expected replica count and document this as a required operational step, or enforce rate limiting at the ingress/API-gateway layer (e.g., Nginx, Envoy, or a Kubernetes Gateway API policy) before requests reach individual pods.

### Proof of Concept
**Preconditions:** 2 web3 service replicas behind a round-robin load balancer, default `requestsPerSecond = 500`.

**Steps:**
1. Identify the load-balanced endpoint, e.g., `https://web3.example.com/api/v1/contracts/call`.
2. Send 900 RPS of valid contract call requests (below the per-instance limit of 500 but above the intended global limit):
   ```
   hey -n 9000 -c 100 -q 900 -m POST \
     -H "Content-Type: application/json" \
     -d '{"to":"0x0000000000000000000000000000000000000167","data":"0x","gas":50000}' \
     https://web3.example.com/api/v1/contracts/call
   ```
3. **Expected (correct) behavior:** Requests beyond 500 RPS receive HTTP 429.
4. **Actual behavior:** All 900 RPS succeed with HTTP 200. Each instance receives ~450 RPS (below its local 500-token bucket), so `rateLimitBucket.tryConsume(1)` always returns `true` on both nodes. No `ThrottleException` is thrown. Aggregate backend load is 900 EVM executions/second — 80% above the intended cap. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L41-44)
```java
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
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
