### Title
Global Single-Token Rate Bucket Allows Unprivileged User to Monopolize the Opcodes Endpoint (Low-and-Slow DoS)

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint uses a single, server-wide `opcodeRateLimitBucket` with a default capacity of 1 token/second and no per-IP or per-user partitioning. A single unauthenticated attacker sending exactly 1 request per second — the full global budget — permanently monopolizes the endpoint for all other users while never triggering a throttle rejection. Because each accepted request triggers a full, synchronous EVM re-execution that can run for several seconds, concurrent in-flight executions accumulate, exhausting server threads and CPU.

### Finding Description

**Code path:**

`OpcodesController.getContractOpcodes()` (lines 59–64) calls `throttleManager.throttleOpcodeRequest()` before dispatching to `opcodeService.processOpcodeCall()`. [1](#0-0) 

`ThrottleManagerImpl.throttleOpcodeRequest()` (lines 52–56) performs a single `opcodeRateLimitBucket.tryConsume(1)` check — no IP address, session, or identity is consulted. [2](#0-1) 

`ThrottleConfiguration.opcodeRateLimitBucket()` (lines 47–55) creates one JVM-wide `Bucket` with `capacity = opcodeRequestsPerSecond` (default: **1**), refilling greedily at 1 token/second. No `SynchronizationStrategy` is set, and no per-client state exists. [3](#0-2) 

`ThrottleProperties.opcodeRequestsPerSecond` defaults to `1`. [4](#0-3) 

**Root cause — failed assumption:** The design assumes that 1 req/sec globally is low enough to prevent abuse. It fails to account for the fact that a single client can consume the entire global budget, and that `tryConsume` is non-blocking — it does not wait for the previous EVM re-execution to finish before the next token becomes available. The Javadoc for the endpoint itself acknowledges: *"the transaction needs to be re-executed on the EVM, which may take a significant amount of time."* [5](#0-4) 

**Exploit flow:**

1. Attacker identifies any valid transaction hash for a high-gas contract call (publicly visible on-chain).
2. Attacker sends `GET /api/v1/contracts/results/{hash}/opcodes?stack=true&memory=true&storage=true` with `Accept-Encoding: gzip` at exactly 1 req/sec.
3. Each request passes `tryConsume(1)` — the token is available because the attacker paces at the refill rate.
4. Each request triggers `contractDebugService.processOpcodeCall(...)`, a synchronous, CPU-bound EVM re-execution.
5. If each re-execution takes T seconds (T > 1), after N seconds there are N concurrent EVM re-executions in flight, bounded only by the server's thread pool and the 10-second `requestTimeout`.
6. All other users receive HTTP 429 because the global bucket is perpetually empty.

**Why existing checks are insufficient:**

- `opcodeRateLimitBucket` is global — no per-IP, per-session, or per-user bucket exists anywhere in the filter chain (`LoggingFilter`, `MetricsFilter`) for this endpoint. [6](#0-5) 
- The `requestTimeout` of 10 seconds limits individual request duration but does not prevent concurrent accumulation of in-flight EVM re-executions.
- The `gasLimitBucket` and `rateLimitBucket` are not consulted for opcode requests — only `opcodeRateLimitBucket` is checked. [2](#0-1) 
- No authentication or authorization is required to call the endpoint.

### Impact Explanation
**Availability — High.** A single attacker with no credentials permanently denies all other users access to the opcodes endpoint by consuming the entire 1 req/sec global budget. Simultaneously, if EVM re-executions are slow (which the code itself documents as expected), the attacker can accumulate concurrent executions that exhaust the server's thread pool and CPU, potentially degrading other endpoints on the same service instance. The endpoint is explicitly described as "heavy," amplifying the resource impact of each accepted request.

### Likelihood Explanation
**High.** No privileges, API keys, or special knowledge are required — only a valid transaction hash (publicly available) and the ability to send HTTP GET requests at 1 req/sec. The attack is trivially scriptable with `curl` or any HTTP client. It is repeatable indefinitely and leaves no distinguishing fingerprint beyond normal request logs. The attacker does not need to exceed the rate limit to cause harm, making detection and automated blocking difficult.

### Recommendation

1. **Per-IP rate limiting:** Replace (or supplement) the single global bucket with a per-IP bucket map (e.g., using Bucket4j's `BucketProxyManager` backed by a `ConcurrentHashMap` or a distributed cache). Each IP should be limited to at most 1 req/sec independently.
2. **Concurrency limit:** Add a `Semaphore` (or a bounded executor) to cap the number of simultaneously executing EVM re-executions (e.g., 2–4), independent of the token-bucket rate. This prevents thread exhaustion even if the rate limit is legitimately consumed.
3. **Authentication/authorization:** Restrict the endpoint to authenticated or trusted clients, since it is already gated by `opcode.tracer.enabled=false` by default and is clearly intended for operator/debug use.
4. **Burst prevention:** Set the bucket's initial tokens to 0 (cold start) and use a `refillIntervally` strategy instead of `refillGreedy` to prevent burst consumption after idle periods.

### Proof of Concept

```bash
# Prerequisites:
# 1. Server running with hiero.mirror.web3.opcode.tracer.enabled=true
# 2. TXHASH = any valid contract transaction hash from the network

TXHASH="0xabc123..."
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<host>/api/v1/contracts/results/${TXHASH}/opcodes?stack=true&memory=true&storage=true"
  sleep 1
done
```

**Expected result:**
- The attacker's requests always return HTTP 200 (token always available at 1 req/sec pace).
- Any concurrent legitimate user request returns HTTP 429 (`Requests per second rate limit exceeded`).
- Server CPU and thread utilization climbs as EVM re-executions accumulate, because `tryConsume` does not block on in-flight request completion.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L36-44)
```java
     * <p>
     * Returns a result containing detailed information for the transaction execution, including all values from the
     * {@code stack}, {@code memory} and {@code storage} and the entire trace of opcodes that were executed during the
     * replay.
     * </p>
     * <p>
     * Note that to provide the output, the transaction needs to be re-executed on the EVM, which may take a significant
     * amount of time to complete if stack and memory information is requested.
     * </p>
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-64)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
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
