### Title
Opcode Replay Endpoint Lacks Gas-Aware Throttling, Enabling CPU Exhaustion via High-Gas Transaction Replay

### Summary
The `getContractOpcodes()` endpoint in `OpcodesController.java` throttles requests using only a global request-count bucket (1 request/second by default), with no accounting for the gas cost of the historical transaction being replayed. Any unauthenticated user can repeatedly target the most computationally expensive historical transactions, forcing full EVM re-execution at maximum CPU cost while consuming the entire global quota and denying service to legitimate users.

### Finding Description

**Code path:**

`OpcodesController.java:61` calls `throttleManager.throttleOpcodeRequest()` before dispatching to `opcodeService.processOpcodeCall(request)`. [1](#0-0) 

`ThrottleManagerImpl.java:52-55` implements `throttleOpcodeRequest()` — it only consumes 1 token from the global `opcodeRateLimitBucket`, regardless of the gas cost of the transaction being replayed: [2](#0-1) 

The `opcodeRateLimitBucket` is a single **global** (not per-IP, not per-user) bucket with a default capacity of `opcodeRequestsPerSecond = 1`: [3](#0-2) [4](#0-3) 

**Contrast with regular contract calls:** `throttle(ContractCallRequest)` applies BOTH a request-count check AND a gas-proportional check via `gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))`. This ensures high-gas calls consume proportionally more tokens. The opcode endpoint has no equivalent gas-aware check: [5](#0-4) 

**Root cause:** The failed assumption is that "1 request/second" is a sufficient proxy for computational cost. A 21,000-gas transfer and a 15,000,000-gas DeFi transaction both consume exactly 1 token, yet their EVM re-execution costs differ by orders of magnitude. There is also no per-IP or per-user isolation — one attacker consumes the entire global quota.

### Impact Explanation

An attacker who sends 1 request/second targeting the highest-gas historical transactions forces the server to perform full EVM re-execution (including stack/memory/storage tracing) at maximum CPU cost. If a single re-execution takes longer than 1 second (plausible for complex DeFi transactions), the server's thread pool can become saturated. Simultaneously, the attacker monopolizes the global `opcodeRateLimitBucket`, returning HTTP 429 to all other legitimate users of the endpoint. This constitutes a denial-of-service against both the opcode tracing feature and, via CPU saturation, potentially the broader web3 service.

### Likelihood Explanation

The endpoint requires no authentication and no API key. The only barrier is the `Accept-Encoding: gzip` header check, which is trivially satisfied. Any attacker can discover high-gas transaction hashes from public blockchain explorers. The attack is fully repeatable and scriptable with a single `curl` command in a loop. The global (not per-IP) nature of the bucket means a single attacker from one IP can exhaust the entire allowance.

### Recommendation

1. **Apply gas-aware throttling to opcode requests.** After resolving the historical transaction's gas used from the database (before EVM re-execution), consume tokens from the existing `gasLimitBucket` proportional to that gas value, mirroring the logic in `throttle(ContractCallRequest)`.
2. **Add per-IP rate limiting** at the reverse-proxy or servlet-filter level so one source IP cannot monopolize the global quota.
3. **Enforce a maximum gas cap** for transactions eligible for opcode replay (e.g., reject requests where the historical transaction's gas used exceeds a configurable threshold).
4. **Require authentication** (API key or similar) for this endpoint, given its explicitly documented high computational cost.

### Proof of Concept

**Preconditions:**
- The `hiero.mirror.web3.opcode.tracer.enabled` property is `true` (the feature is enabled).
- The attacker has identified a high-gas historical transaction hash (e.g., from a public explorer), e.g. `0xABC...` with 15,000,000 gas used.

**Steps:**
```bash
# Attacker script — no credentials needed
while true; do
  curl -s -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/0xABC.../opcodes?stack=true&memory=true&storage=true" \
    -o /dev/null
  sleep 1
done
```

**Result:**
- Each request passes the `opcodeRateLimitBucket` check (1 token consumed).
- The server performs full EVM re-execution of the 15M-gas transaction, consuming maximum CPU.
- All other users of the endpoint receive HTTP 429 (`Requests per second rate limit exceeded`) because the single global token is consumed.
- Under sustained load, server CPU utilization climbs and response latency for the broader web3 service degrades.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-65)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-48)
```java
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L29-29)
```java
    private long opcodeRequestsPerSecond = 1;
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
