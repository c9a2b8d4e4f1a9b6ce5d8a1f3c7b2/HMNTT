### Title
Global Rate-Limit Bucket Allows Single-Source Exhaustion (Application-Layer DoS)

### Summary
`ThrottleManagerImpl.throttle()` enforces a single, process-wide `rateLimitBucket` (default 500 req/s) with no per-IP or per-user partitioning. Any unauthenticated caller that sends ≥500 requests per second from a single source consumes the entire quota, causing every other legitimate caller to receive HTTP 429 for the remainder of that second. The bucket refills greedily, so the attack is trivially repeatable every second.

### Finding Description

**Exact code path:**

`ThrottleConfiguration.rateLimitBucket()` creates one singleton Bucket4j bucket: [1](#0-0) 

The bucket capacity equals `requestsPerSecond` (default 500) and refills greedily at 500 tokens/second — a single shared pool for the entire JVM process.

`ThrottleManagerImpl.throttle()` consumes exactly 1 token per request with no caller identity check: [2](#0-1) 

`ContractController.call()` invokes this before any processing: [3](#0-2) 

**Root cause:** The `rateLimitBucket` bean is a single instance injected as a singleton. There is no `ConcurrentHashMap<IP, Bucket>`, no `X-Forwarded-For` inspection, and no per-caller partitioning anywhere in the throttle stack. [4](#0-3) 

**Why existing checks fail:**

- The `request[]` filter system (`RequestProperties`, `ActionType.THROTTLE`) is opt-in, requires operator configuration, and is also global per-filter — it does not provide per-IP isolation. [5](#0-4) 

- The GCP gateway `maxRatePerEndpoint: 250` is a per-backend-pod limit (not per-client-IP), is gated behind `global.gateway.enabled: false` by default, and is explicitly noted as requiring HPA changes to take effect. [6](#0-5) 

- `gasLimitBucket` uses `SynchronizationStrategy.SYNCHRONIZED` but `rateLimitBucket` does not — however both are still single global pools. [7](#0-6) 

### Impact Explanation

A single unauthenticated attacker can send 500 HTTP POST requests per second to `/api/v1/contracts/call` and consume the entire global `rateLimitBucket`. Every other caller receives `HTTP 429 Too Many Requests` for that second. Because the bucket refills greedily every second, the attacker can sustain this indefinitely. This constitutes a complete application-layer denial of service for all legitimate users of the web3 JSON-RPC endpoint, which is the primary EVM-compatible interface of the mirror node. The severity matches the stated scope: 100% of request-processing capacity is monopolized (well above the 30% threshold), without any brute-force or network-flooding requirement.

### Likelihood Explanation

**Preconditions:** None. No authentication, no API key, no account required. The endpoint is publicly accessible.

**Attacker capability:** Sending 500 HTTP POST requests per second from a single host is trivially achievable with tools like `wrk`, `hey`, `ab`, or a simple multi-threaded script. A single commodity server or even a cloud VM can sustain this rate.

**Repeatability:** The attack is fully repeatable every second because `refillGreedy(rateLimit, Duration.ofSeconds(1))` restores all 500 tokens at the start of each second window. The attacker simply maintains a steady 500 req/s stream.

**Detection/mitigation difficulty:** Without per-IP tracking in the application, operators cannot distinguish the attack from legitimate high-volume traffic at the application layer. Infrastructure-level mitigations (GCP gateway) are optional and not enabled by default.

### Recommendation

1. **Per-IP rate limiting:** Replace the single global `rateLimitBucket` with a `ConcurrentHashMap<String, Bucket>` keyed on the client IP (extracted from `X-Forwarded-For` or `HttpServletRequest.getRemoteAddr()`). Each IP gets its own bucket with a per-IP cap (e.g., 50 req/s), while the global cap remains as a secondary guard.

2. **Alternatively, use Bucket4j's built-in distributed/keyed support** or a library like Resilience4j's `RateLimiter` with per-key semantics.

3. **Enable and enforce the GCP gateway per-client-IP rate limit** (`maxRatePerEndpoint` with `sessionAffinity: CLIENT_IP`) as a defense-in-depth layer, but do not rely on it as the sole control since it is infrastructure-dependent and disabled by default.

4. **Short-term:** Lower `requestsPerSecond` to a value that limits damage from a single source, and document that per-IP limiting is required for production deployments.

### Proof of Concept

```bash
# Attacker sends 500 req/s from a single host, exhausting the global bucket
wrk -t10 -c100 -d60s -s post.lua http://<mirror-node-host>:8545/api/v1/contracts/call

# post.lua:
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body = '{"to":"0x0000000000000000000000000000000000000167","data":"0x","gas":21000}'
```

**Expected result:** After the first ~500 requests in any given second, all subsequent requests from any source (including legitimate users) receive:
```
HTTP/1.1 429 Too Many Requests
{"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

This continues for as long as the attacker maintains ≥500 req/s, which is trivially sustainable from a single commodity machine.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L28-29)
```java
    @Qualifier(RATE_LIMIT_BUCKET)
    private final Bucket rateLimitBucket;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-41)
```java
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L44-61)
```java
    @Override
    public boolean test(ContractCallRequest contractCallRequest) {
        if (rate == 0 || counter.getAndIncrement() >= limit) {
            return false;
        }

        if (action != ActionType.THROTTLE && RandomUtils.secure().randomLong(0L, 100L) >= rate) {
            return false;
        }

        for (var filter : filters) {
            if (filter.test(contractCallRequest)) {
                return true;
            }
        }

        return filters.isEmpty();
    }
```

**File:** charts/hedera-mirror-web3/values.yaml (L56-58)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
```
