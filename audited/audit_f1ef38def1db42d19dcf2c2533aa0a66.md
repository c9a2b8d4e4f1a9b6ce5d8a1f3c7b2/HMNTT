### Title
Global Singleton `rateLimitBucket` Allows Single Unprivileged User to Starve All Other Clients via Token Exhaustion

### Summary
The `rateLimitBucket` bean in `ThrottleConfiguration.java` is a single application-wide token bucket with no per-user, per-IP, or per-connection partitioning. Any unauthenticated caller can continuously consume tokens at the full refill rate, keeping the bucket perpetually near-empty and causing all concurrent legitimate users to receive `ThrottleException` (HTTP 429). No privilege is required and no existing check prevents a single source from monopolizing the entire global budget.

### Finding Description
**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, `rateLimitBucket()`, lines 24–32: [1](#0-0) 

A single `Bucket` is created with capacity = `requestsPerSecond` (default **500**) and a greedy refill of 500 tokens/second. It is registered as a Spring singleton bean, meaning every thread in the JVM shares the same object.

`web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, `throttle()`, lines 37–42: [2](#0-1) 

Every incoming request calls `rateLimitBucket.tryConsume(1)`. There is no caller identity check, no IP lookup, no session key — just a single atomic decrement on the shared counter.

**Root cause / failed assumption:** The design assumes the 500 req/s global ceiling is large enough that no single caller will saturate it. That assumption fails for a public, unauthenticated endpoint: a single attacker can issue requests at exactly the refill rate, keeping available tokens at 0–1 at all times.

**Why existing checks are insufficient:**

- `LoggingFilter` only logs; it performs no rate limiting. [3](#0-2) 
- `MetricsFilter` only records byte counts. [4](#0-3) 
- `RequestProperties` per-filter buckets are only consulted **after** the global bucket passes, and only when an operator has configured explicit `THROTTLE` rules — none are configured by default. [5](#0-4) 
- The default `requestsPerSecond = 500` is the only guard. [6](#0-5) 

### Impact Explanation
Any legitimate user sharing the node during an attack receives HTTP 429 `ThrottleException` for the duration of the attack. Because the mirror node's web3 API is the primary EVM simulation and `eth_call` surface for dApps and tooling, sustained exhaustion effectively takes the node's web3 service offline for all other clients without touching consensus. The `opcodeRateLimitBucket` (default: **1 req/s**) is even more trivially exhausted by a single attacker request per second. [7](#0-6) 

### Likelihood Explanation
- **No authentication required** — the endpoint is public.
- **No amplification needed** — 1 token consumed per request, attacker sends ≤500 req/s.
- **Trivially scriptable** — a simple `while true; do curl ...; done` loop from a single machine with adequate bandwidth suffices.
- **Undetectable at the application layer** — the application has no IP-awareness; all requests look identical.
- **Repeatable indefinitely** — the bucket refills every second, so the attacker simply keeps pace with the refill rate.

### Recommendation
1. **Add per-source rate limiting** using a `ConcurrentHashMap<String, Bucket>` keyed on client IP (or `X-Forwarded-For` behind a proxy), so each caller gets its own sub-bucket whose capacity is a fraction of the global limit.
2. **Enforce a per-IP hard cap** at the servlet filter level (before `ThrottleManagerImpl`) so a single IP cannot consume more than `requestsPerSecond / N` tokens per second.
3. **Alternatively**, deploy an external rate-limiting layer (API gateway, WAF, or Nginx `limit_req`) that enforces per-IP limits before traffic reaches the application.
4. Consider replacing the single global bucket with bucket4j's `ProxyManager` backed by a distributed store if multiple nodes share load.

### Proof of Concept
```bash
# Attacker: sustain ~499 req/s to keep the bucket near-empty
# (adjust --rate to match requestsPerSecond - 1)
ab -n 100000 -c 50 -p body.json -T application/json \
   http://<mirror-node-host>/api/v1/contracts/call

# Victim (concurrent, different IP or thread):
curl -X POST http://<mirror-node-host>/api/v1/contracts/call \
     -H 'Content-Type: application/json' \
     -d '{"data":"0x...","to":"0x...","gas":50000}'
# Expected result while attacker runs:
# HTTP 429 Too Many Requests
# {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

The victim's request hits `rateLimitBucket.tryConsume(1)` on an empty bucket and receives `ThrottleException` immediately, with no recourse until the attacker stops. [8](#0-7)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L44-48)
```java
        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L39-54)
```java
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        long start = System.currentTimeMillis();
        Exception cause = null;

        if (!(request instanceof ContentCachingRequestWrapper)) {
            request = new ContentCachingRequestWrapper(request, web3Properties.getMaxPayloadLogSize() * 10);
        }

        try {
            filterChain.doFilter(request, response);
        } catch (Exception t) {
            cause = t;
        } finally {
            logRequest(request, response, start, cause);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/MetricsFilter.java (L49-57)
```java
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            recordMetrics(request, response);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
