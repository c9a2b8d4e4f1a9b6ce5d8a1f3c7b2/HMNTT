### Title
Global RPS Bucket Monopolization — Single-IP Starvation of All Other Callers

### Summary
`ThrottleManagerImpl.throttle()` gates every `/api/v1/contracts/call` request against a single, process-wide `rateLimitBucket` with no per-source-IP subdivision. Any unprivileged caller that can reach the node can saturate the entire `requestsPerSecond` budget (default 500 RPS), causing every concurrent request from every other IP to receive a `ThrottleException` for the remainder of that one-second window. During a network partition, upstream defenses (load balancers, WAFs, API gateways) that normally enforce per-client limits are absent, making the in-process bucket the sole protection — and it provides none against a single aggressive sender.

### Finding Description
**Exact code path:**

`ThrottleManagerImpl.throttle()` — `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 37–42:
```java
public void throttle(ContractCallRequest request) {
    if (!rateLimitBucket.tryConsume(1)) {          // ← single global bucket
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    } else if (!gasLimitBucket.tryConsume(...)) {
        ...
    }
``` [1](#0-0) 

The `rateLimitBucket` bean is constructed once as a single application-scoped `Bucket` in `ThrottleConfiguration.rateLimitBucket()`:
```java
@Bean(name = RATE_LIMIT_BUCKET)
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond();   // default 500
    ...
    return Bucket.builder().addLimit(limit).build();
}
``` [2](#0-1) 

**Root cause:** The `ContractCallRequest` model carries no source-IP field, and `ThrottleManagerImpl` never inspects `HttpServletRequest` or any IP-keyed structure. The `request[]` filter system (`RequestFilter.FilterField`) enumerates only `BLOCK`, `DATA`, `ESTIMATE`, `FROM`, `GAS`, `TO`, `VALUE` — source IP is not a filterable dimension: [3](#0-2) 

There is therefore no mechanism — neither in the global bucket path nor in the configurable `request[]` filter path — to isolate one caller's consumption from another's.

**Failed assumption:** The design assumes that per-IP enforcement is handled by an upstream layer (reverse proxy, load balancer). During a network partition that isolates the node, that assumption breaks and the application-level throttle becomes the only control.

### Impact Explanation
A single attacker IP can fire 500 concurrent or sequential requests within one second, draining all tokens from `rateLimitBucket`. Every other client hitting the same node during that window receives HTTP 429 (`ThrottleException: Requests per second rate limit exceeded`). Because the bucket refills greedily at `requestsPerSecond` tokens per second, the attacker can sustain this indefinitely by maintaining a steady 500 req/s stream. The gas bucket (`gasLimitBucket`) provides a secondary ceiling, but with the minimum gas value of 21,000 and `GAS_SCALE_FACTOR = 10,000`, each request consumes only 2 gas tokens, so the gas bucket is not a meaningful barrier at 500 RPS. [4](#0-3) 

**Severity: High** — complete denial of service for all legitimate users on the isolated node, with zero authentication or privilege required.

### Likelihood Explanation
**Preconditions:** Network reachability to the node's HTTP port; no credentials needed. During a partition the node is reachable by any host on the same network segment.

**Feasibility:** Trivially reproducible with standard HTTP benchmarking tools (`wrk`, `ab`, `hey`). No exploit code required. The attacker does not need to know anything about the contract ABI — a minimal valid `ContractCallRequest` JSON body suffices.

**Repeatability:** Continuous; the attacker simply maintains the request rate. The bucket refills every second, so the attack must be sustained, but that is trivially achievable.

### Recommendation
1. **Per-IP token buckets:** Maintain a `ConcurrentHashMap<String, Bucket>` keyed on the resolved client IP (respecting `X-Forwarded-For` with a trusted-proxy allowlist). Each IP gets its own bucket sized to `requestsPerSecond / expectedConcurrentClients` or a configurable per-IP cap.
2. **Add `SOURCE_IP` as a `FilterField`:** Extend `RequestFilter.FilterField` and `ContractCallRequest` (or pass `HttpServletRequest` into `throttle()`) so operators can configure `REJECT`/`THROTTLE` rules targeting specific IPs or CIDR ranges without code changes.
3. **Upstream enforcement:** Document that the application-level throttle is not a substitute for per-IP rate limiting at the ingress layer, and add a startup warning when no upstream proxy is detected.

### Proof of Concept
```bash
# Attacker: drain the global bucket (default 500 RPS) from a single IP
wrk -t10 -c500 -d60s \
  -s <(echo 'wrk.method="POST"
              wrk.headers["Content-Type"]="application/json"
              wrk.body='"'"'{"to":"0x0000000000000000000000000000000000000001","gas":21000}'"'"'') \
  http://<isolated-node>:8080/api/v1/contracts/call

# Victim (different IP, same node): all requests rejected
curl -X POST http://<isolated-node>:8080/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":21000}'
# → HTTP 429: {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

While the attacker sustains ≥500 req/s, the victim receives 429 on every attempt. The attack requires no authentication, no special knowledge of the contract system, and is effective against any node where upstream per-IP rate limiting is absent — the exact condition that holds during a network partition.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L39-46)
```java
    enum FilterField {
        BLOCK(ContractCallRequest::getBlock),
        DATA(ContractCallRequest::getData),
        ESTIMATE(ContractCallRequest::isEstimate),
        FROM(ContractCallRequest::getFrom),
        GAS(ContractCallRequest::getGas),
        TO(ContractCallRequest::getTo),
        VALUE(ContractCallRequest::getValue);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L18-35)
```java
    private static final long GAS_SCALE_FACTOR = 10_000L;

    @Min(0)
    @Max(100)
    private float gasLimitRefundPercent = 100;

    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;
```
