### Title
Global Shared Rate-Limit Bucket Allows Unprivileged Attacker to Exhaust Entire 500 RPS Budget (DoS via Token Starvation)

### Summary
`rateLimitBucket` in `ThrottleConfiguration.java` is a single, process-wide, in-memory Bucket4j token bucket with no per-IP or per-session partitioning. Any unauthenticated external caller who can open multiple TCP connections or rotate source IPs can consume all 500 tokens per second, reducing every other legitimate caller's effective quota to zero and causing them to receive HTTP 429 indefinitely for as long as the flood continues.

### Finding Description

**Exact code path:**

`ThrottleConfiguration.rateLimitBucket()` (lines 25–32) constructs one singleton `Bucket` with capacity = `requestsPerSecond` (default 500) and a greedy refill of 500 tokens/second: [1](#0-0) 

`ThrottleManagerImpl.throttle()` (line 38) calls `rateLimitBucket.tryConsume(1)` for every inbound request, with no key derived from source IP, session, API key, or any other caller identity: [2](#0-1) 

**Root cause — failed assumption:** The design assumes that the 500 RPS ceiling is high enough that no single caller will naturally saturate it, and that upstream infrastructure (load balancer / WAF) will enforce per-IP limits. Neither assumption is enforced in the application code.

**Why existing checks are insufficient:**

- `LoggingFilter` reads `request.getRemoteAddr()` only for log output; it performs no rate-limiting action on it. [3](#0-2) 
- `MetricsFilter` records byte counts only; no rate enforcement. [4](#0-3) 
- `RequestFilter` can match on the `FROM` field (the Ethereum sender address in the JSON body), but that field is fully attacker-controlled and is not the network source address. [5](#0-4) 
- There is no Spring Security configuration, no servlet filter, and no other code in `web3/src/main/java/` that tracks or limits requests by source IP.
  

**Exploit flow:**

1. Attacker opens N concurrent HTTP connections (or uses N cloud VMs / a botnet) and sends `eth_call` / `eth_estimateGas` POST requests to `/api/v1/contracts/call`.
2. Each request hits `ThrottleManagerImpl.throttle()`, which calls `rateLimitBucket.tryConsume(1)`.
3. Once the attacker's aggregate rate reaches 500 RPS, the bucket is empty.
4. Every subsequent request from any source — including legitimate users — returns `ThrottleException("Requests per second rate limit exceeded")` → HTTP 429.
5. The bucket refills at 500 tokens/second; the attacker simply keeps pace, maintaining starvation indefinitely.

### Impact Explanation

Complete denial of service for all legitimate callers of the web3 JSON-RPC endpoint. Because the bucket is shared and in-memory, the attack is instantaneous and requires no authentication, no special protocol knowledge, and no state beyond the ability to send HTTP POST requests. The `gasLimitBucket` and `opcodeRateLimitBucket` are equally unpartitioned and susceptible to the same attack. [6](#0-5) 

### Likelihood Explanation

The attack requires only a commodity HTTP client and either multiple source IPs (trivially obtained via cloud providers or residential proxies) or a single high-bandwidth host that can sustain 500 HTTP requests/second (well within reach of a single modern machine). No credentials, no prior knowledge of the system, and no vulnerability chaining are needed. The attack is fully repeatable and can be automated in under 20 lines of code.

### Recommendation

1. **Per-IP token buckets:** Replace the single shared `Bucket` with a `ConcurrentHashMap<String, Bucket>` keyed on the resolved client IP (respecting `X-Forwarded-For` behind a trusted proxy). Bucket4j's `ProxyManager` abstraction supports this pattern directly.
2. **Enforce a per-IP sub-limit:** Even if a global cap is retained, add a secondary per-IP bucket (e.g., 50 RPS per IP) so no single source can monopolize the global budget.
3. **Upstream enforcement:** Deploy a WAF or API gateway (e.g., nginx `limit_req`, AWS WAF, Cloudflare) with per-IP rate limiting as a defense-in-depth layer before requests reach the JVM.
4. **Authenticate callers:** Require an API key or JWT so that rate limits can be enforced per authenticated identity rather than per IP, which is harder to spoof.

### Proof of Concept

```bash
# Requires: Apache Bench or wrk; adjust -c (concurrency) and -n (requests) as needed.
# Single source IP, 600 concurrent connections, 10 000 requests total:
ab -n 10000 -c 600 -p payload.json -T application/json \
   http://<mirror-node-host>/api/v1/contracts/call

# payload.json — minimal valid eth_call body:
# {"data":"0x","to":"0x0000000000000000000000000000000000000001","gas":21000}

# Expected result after ~500 requests in the first second:
# HTTP/1.1 429 Too Many Requests
# {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}

# All subsequent requests from ANY other client during that second also receive 429.
```

With multiple source IPs (e.g., using `wrk` from several cloud VMs simultaneously), the starvation is maintained across refill cycles, producing a sustained outage for all legitimate users.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L69-69)
```java
                new Object[] {request.getRemoteAddr(), request.getMethod(), uri, elapsed, status, message, content};
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
