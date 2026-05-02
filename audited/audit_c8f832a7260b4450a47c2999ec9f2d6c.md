### Title
Global Token Bucket Exhaustion Enabling Thundering Herd Retry Storm via Absent Backpressure and No `Retry-After` Header

### Summary
The `rateLimitBucket` in `ThrottleConfiguration.java` is a single global bucket shared across all clients with no per-IP partitioning. When an unprivileged attacker exhausts it, all clients receive HTTP 429 with no `Retry-After` header, causing them to retry aggressively and in an uncoordinated fashion. This creates a self-sustaining retry storm that keeps the bucket exhausted even after the attacker reduces their own request rate.

### Finding Description
**Code path:**

- `ThrottleConfiguration.java` lines 24–32: `rateLimitBucket()` creates a single global `Bucket` with `refillGreedy(rateLimit, Duration.ofSeconds(1))` and no `SynchronizationStrategy` override. No per-client or per-IP partitioning exists.
- `ThrottleManagerImpl.java` lines 37–39: `rateLimitBucket.tryConsume(1)` is called non-blocking — if the bucket is empty, `ThrottleException` is thrown immediately with no queuing, no wait hint, and no token reservation.
- `GenericControllerAdvice.java` lines 134–137: `throttleException` maps to HTTP 429 `TOO_MANY_REQUESTS` with no `Retry-After` header and no backoff guidance.

**Root cause and failed assumption:**

The design assumes that clients will self-regulate retries after receiving 429. In reality, without a `Retry-After` header, HTTP clients (including web3 libraries, JSON-RPC proxies, and scripted callers) default to immediate or fixed-interval retries. The global bucket has no fairness mechanism — any single attacker with connections exceeding `requestsPerSecond` (default: 500) can exhaust it entirely.

**Exploit flow:**

1. Attacker opens >500 concurrent connections and fires requests simultaneously, exhausting the global bucket.
2. All clients — attacker and legitimate users alike — receive HTTP 429.
3. With no `Retry-After` header, legitimate clients retry after their own fixed interval (often 0–1 s).
4. On retry, all clients hit the bucket simultaneously. `refillGreedy` distributes tokens continuously (~1 token/2 ms at 500 req/s), but the flood of retrying clients consumes each token the instant it appears.
5. The attacker needs only maintain a request rate ≥ the refill rate (500 req/s) to keep the bucket perpetually empty. Legitimate clients' own retry storms amplify this, meaning the attacker can reduce their own rate and still sustain the DoS.

**Why existing checks are insufficient:**

- `tryConsume(1)` is purely non-blocking with no queuing — there is no mechanism to absorb burst retries.
- The `gasLimitBucket` uses `SynchronizationStrategy.SYNCHRONIZED` (line 42), but `rateLimitBucket` does not, and neither has per-IP isolation.
- No middleware (servlet filter, Spring Security, reverse proxy config) enforces per-IP limits in the in-scope code.
- The 429 response body contains only a generic error message; no `Retry-After`, `X-RateLimit-Reset`, or backoff hint is emitted.

### Impact Explanation
Any unprivileged external user can render the web3 JSON-RPC endpoint unavailable to all legitimate callers for an indefinite period. The attacker sustains the attack at minimal cost (500 req/s is achievable from a single machine). Legitimate users experience continuous 429 responses with no actionable retry guidance, effectively a full service denial. Classified as griefing/DoS with no direct economic damage to the network, consistent with the stated Medium scope.

### Likelihood Explanation
No authentication or account is required. The attack requires only a standard HTTP client capable of 500+ concurrent requests per second — trivially achievable with tools like `wrk`, `hey`, or a small script. The attack is repeatable, stateless, and requires no prior knowledge of the system beyond the public API endpoint. The absence of any IP-based rate limiting or upstream WAF in the in-scope configuration means there is no compensating control.

### Recommendation
1. **Add `Retry-After` header** to all 429 responses in `GenericControllerAdvice.throttleException` to stagger client retries and break retry synchronization.
2. **Implement per-IP rate limiting** using a keyed bucket (e.g., `bucket4j` with a `Map<String, Bucket>` keyed by client IP, or a `ProxyManager` backed by a cache) so one attacker cannot exhaust the global budget.
3. **Use `refillIntervally` with jitter** or expose a `X-RateLimit-Reset` timestamp so clients can compute a randomized backoff, preventing synchronized retry storms.
4. **Apply `SynchronizationStrategy.SYNCHRONIZED`** (or `LOCK_FREE`) consistently to `rateLimitBucket` as is already done for `gasLimitBucket`.

### Proof of Concept
```bash
# Step 1: Exhaust the global bucket (default 500 req/s)
# Run from a single machine with a tool like 'hey':
hey -n 10000 -c 600 -m POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{},"latest"],"id":1}' \
  http://<mirror-node-host>/api/v1/contracts/call

# Step 2: Observe that all concurrent legitimate clients receive HTTP 429
# with no Retry-After header:
curl -i -X POST http://<mirror-node-host>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{},"latest"],"id":1}'
# Expected: HTTP/1.1 429 Too Many Requests
# No Retry-After header present

# Step 3: Reduce attacker rate to ~500 req/s and observe that
# legitimate clients' own retry storms sustain the exhaustion —
# the bucket never recovers above 0 tokens.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L134-137)
```java
    @ExceptionHandler
    private ResponseEntity<?> throttleException(final ThrottleException e, final WebRequest request) {
        return handleExceptionInternal(e, null, null, TOO_MANY_REQUESTS, request);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
