### Title
Global Opcode Rate-Limit Bucket Exhaustion by Single Unprivileged Client

### Summary
`ThrottleManagerImpl.throttleOpcodeRequest()` guards the `/contracts/results/{transactionIdOrHash}/opcodes` endpoint with a single, process-wide `opcodeRateLimitBucket` that is not partitioned by source IP or any user identity. Because the default quota is 1 request per second globally, a single unauthenticated client sending one request per second continuously monopolises the entire quota, causing every other user to receive HTTP 429 for the duration of the attack.

### Finding Description
**Exact code path:**

`ThrottleManagerImpl.throttleOpcodeRequest()` (lines 52–55): [1](#0-0) 

The bucket is a singleton Spring bean constructed in `ThrottleConfiguration.opcodeRateLimitBucket()` (lines 47–55): [2](#0-1) 

Its capacity is `opcodeRequestsPerSecond`, which defaults to **1** token per second: [3](#0-2) 

**Root cause:** `tryConsume(1)` is called against this single shared bucket with no caller identity (IP, session, API key) involved. The entire codebase has no per-IP rate-limiting layer — `LoggingFilter` reads `request.getRemoteAddr()` only for logging, not for throttling: [4](#0-3) 

No other `Filter` or `HandlerInterceptor` in the config package performs per-IP throttling:


**Exploit flow:**
1. Attacker sends `GET /api/v1/contracts/results/<any_valid_hash>/opcodes` with `Accept-Encoding: gzip` at ≥1 req/s.
2. Each request calls `throttleOpcodeRequest()`, which drains the 1-token global bucket.
3. All concurrent legitimate requests find the bucket empty and receive `ThrottleException` → HTTP 429.
4. The bucket refills at 1 token/s, but the attacker immediately re-drains it, sustaining the denial indefinitely.

**Why existing checks fail:** The `rateLimitBucket` (general RPS guard, default 500 RPS) is checked in `throttle()`, not in `throttleOpcodeRequest()`. The opcode path bypasses the general rate limiter entirely and goes straight to the 1-token global bucket with no identity dimension. [5](#0-4) 

### Impact Explanation
When `hiero.mirror.web3.opcode.tracer.enabled=true`, the opcode replay endpoint becomes completely unavailable to all users except the attacker. Because the endpoint re-executes transactions on the EVM (noted as "heavy" in the docs), even a 1 RPS denial is operationally significant. Severity matches the stated "Medium / griefing" classification: no funds are at risk, but legitimate access to a resource-intensive diagnostic endpoint is fully blocked.

### Likelihood Explanation
Precondition: the operator has set `hiero.mirror.web3.opcode.tracer.enabled=true` (disabled by default). Once enabled, the attack requires zero privileges, zero authentication, and only 1 HTTP request per second — trivially achievable with `curl`, a browser, or any scripting tool. The attack is repeatable indefinitely and requires no special knowledge of the system beyond the public API path.

### Recommendation
Replace the single global bucket with a per-IP (or per-authenticated-identity) bucket map, e.g. using a `ConcurrentHashMap<String, Bucket>` keyed on `HttpServletRequest.getRemoteAddr()` (or the `X-Forwarded-For` header when behind a proxy). Alternatively, enforce a per-IP sub-limit at the reverse-proxy/ingress layer (e.g. nginx `limit_req_zone`) so that no single source can consume more than a configured fraction of the global quota. A combined approach (per-IP bucket + global bucket) is most robust.

### Proof of Concept
```bash
# Precondition: opcode tracer is enabled on the target instance
# Step 1 – attacker terminal: exhaust the global 1 RPS bucket continuously
while true; do
  curl -s -o /dev/null \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/0x<valid_tx_hash>/opcodes"
  sleep 0.9   # slightly under 1 s to stay ahead of refill
done

# Step 2 – victim terminal: every request returns HTTP 429
curl -v \
  -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/0x<valid_tx_hash>/opcodes"
# Expected: HTTP/1.1 429 Too Many Requests
#           {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L36-56)
```java
    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }

    @Override
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L47-55)
```java
    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L29-29)
```java
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L69-69)
```java
                new Object[] {request.getRemoteAddr(), request.getMethod(), uri, elapsed, status, message, content};
```
