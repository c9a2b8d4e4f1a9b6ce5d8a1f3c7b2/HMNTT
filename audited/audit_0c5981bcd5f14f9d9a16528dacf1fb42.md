### Title
Global Token Bucket Starvation via Unauthenticated Burst Flooding in `ThrottleManagerImpl`

### Summary
The `rateLimitBucket` in `ThrottleManagerImpl` is a single application-wide singleton with no per-source (IP/user) partitioning. Any unauthenticated caller can send a burst of exactly `requestsPerSecond` (default: 500) requests to drain the entire global token bucket, leaving zero tokens for all other users until the bucket refills. Because `refillGreedy` accumulates tokens continuously rather than resetting at a fixed boundary, the attacker simply waits for the bucket to refill (~1 second) and repeats, sustaining a near-total denial of service against the web3 API.

### Finding Description

**Exact code path:**

`ThrottleConfiguration.java` constructs `rateLimitBucket` as a Spring `@Bean` singleton:

```java
// ThrottleConfiguration.java lines 24-32
@Bean(name = RATE_LIMIT_BUCKET)
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond(); // default 500
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)
            .refillGreedy(rateLimit, Duration.ofSeconds(1))
            .build();
    return Bucket.builder().addLimit(limit).build();
}
```

`ThrottleManagerImpl.throttle()` consumes from this single shared bucket for every request from every source:

```java
// ThrottleManagerImpl.java line 38
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
}
```

**Root cause:** There is no per-IP, per-session, or per-identity bucket. The entire `requestsPerSecond` capacity is shared globally. The failed assumption is that the global limit is sufficient to prevent a single source from monopolizing it.

**Exploit flow:**
1. Attacker opens 500 concurrent HTTP connections (or uses async HTTP/2 multiplexing) and fires 500 requests simultaneously at T=0.
2. All 500 tokens are consumed atomically via `tryConsume(1)` calls; bucket reaches 0.
3. Every subsequent request from any legitimate user hits `tryConsume(1) == false` and receives HTTP 429 for the remainder of the refill window.
4. With `refillGreedy`, tokens accumulate at 500 tokens/second. After ~1 second the bucket is full again.
5. Attacker repeats the burst. The cycle sustains indefinitely.

**Why existing checks fail:**
- The `RequestProperties` filter-based throttling (`THROTTLE` action) is content-based (DATA, BLOCK, FROM field matching), not source-IP-based, and is opt-in via configuration — disabled by default (`request = List.of()`).
- The Helm chart `maxRatePerEndpoint: 250` is a GCP gateway-level setting per backend pod, not per source IP, and is optional infrastructure (`global.middleware: false` by default).
- No authentication is required to call the web3 API endpoints.

### Impact Explanation
A single unauthenticated attacker can render the entire Hiero Mirror Node web3 API (contract calls, gas estimation, eth_call) unavailable to all legitimate users. The attack is sustained and repeatable with no cost beyond sending HTTP requests. The default capacity of 500 RPS is trivially achievable with a single machine using async HTTP clients.

### Likelihood Explanation
Preconditions: none — no account, no credentials, no privileged access required. The attacker needs only network access to the web3 endpoint. The burst pattern is trivially implemented with any HTTP load tool (e.g., `wrk`, `hey`, `ab`). The attack is repeatable every ~1 second indefinitely and is not self-limiting.

### Recommendation
Replace the single global bucket with per-source-IP buckets using a `ConcurrentHashMap<String, Bucket>` keyed on the client IP (extracted from `X-Forwarded-For` or `RemoteAddr`). Each IP gets its own `refillGreedy` bucket with a per-IP capacity (e.g., `requestsPerSecond / expectedConcurrentClients`). Alternatively, enforce per-IP rate limiting at the ingress/gateway layer unconditionally (not as an optional Helm value), and reduce the global bucket to a secondary backstop.

### Proof of Concept
```bash
# Drain the global bucket in one burst (default 500 RPS limit)
# Using 'hey' HTTP benchmarking tool:
hey -n 500 -c 500 -m POST \
  -H "Content-Type: application/json" \
  -d '{"data":"0x","estimate":false}' \
  http://<mirror-node-web3-host>/api/v1/contracts/call

# All 500 requests succeed (HTTP 200).
# Immediately after, any request from any other client receives HTTP 429:
curl -X POST http://<mirror-node-web3-host>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"data":"0x","estimate":false}'
# Response: 429 Too Many Requests

# Repeat the burst every ~1 second to sustain the DoS.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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
