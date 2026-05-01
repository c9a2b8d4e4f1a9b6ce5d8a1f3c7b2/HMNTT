### Title
Unauthenticated Global Rate Limit on Opcodes Endpoint Enables Single-Attacker DoS via EVM Re-execution Monopolization

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint requires no authentication and enforces only a single global (not per-client) token-bucket rate limit of 1 request/second. A single anonymous attacker can continuously consume the entire global budget, permanently denying all legitimate users access to the endpoint while triggering expensive full EVM re-executions with no accountability or means of attribution.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` (lines 52–68) accepts any unauthenticated HTTP GET request. The only guards are:
1. A gzip `Accept-Encoding` header check (trivially satisfied by any HTTP client)
2. A call to `throttleManager.throttleOpcodeRequest()` (line 61) [1](#0-0) 

`ThrottleManagerImpl.throttleOpcodeRequest()` consumes from a single shared `opcodeRateLimitBucket` bean: [2](#0-1) 

This bucket is a single application-scoped singleton, configured with a default of `opcodeRequestsPerSecond = 1`: [3](#0-2) 

The bucket is created without `SynchronizationStrategy.SYNCHRONIZED` (unlike `gasLimitBucket`), using the default lock-free strategy: [4](#0-3) 

**Root cause:** The rate limit is global across all clients, not per-IP or per-identity. There is no authentication, no API key, and no per-client tracking. The entire config directory contains no Spring Security configuration:



**Failed assumption:** The design assumes the 1 req/sec global limit is protective, but it is shared across all callers. One attacker consuming it at the maximum rate starves all legitimate users.

**Exploit flow:**
1. Attacker sends `GET /api/v1/contracts/results/<any_valid_tx_hash>/opcodes` with `Accept-Encoding: gzip` at 1 req/sec continuously.
2. Each request passes the gzip check and consumes the single global token.
3. The `opcodeService.processOpcodeCall()` triggers a full EVM re-execution (explicitly documented as potentially taking "a significant amount of time").
4. All subsequent requests from any other client within that second receive HTTP 429.
5. The attacker repeats indefinitely with zero credentials required. [5](#0-4) 

### Impact Explanation

The opcodes endpoint is completely monopolized by a single unauthenticated attacker. Legitimate users (e.g., developers debugging contract executions) receive 429 responses for the entire duration of the attack. Each attacker-triggered request forces a full EVM re-execution, consuming CPU and memory on the mirror node. Because the global budget is 1 req/sec and there is no per-client sub-limit, even a single-threaded attacker achieves 100% denial of service for this endpoint with no resource cost to themselves beyond sending one HTTP request per second. [3](#0-2) 

### Likelihood Explanation

Preconditions are minimal: the attacker needs only a valid transaction hash (publicly available on-chain) and an HTTP client that sets `Accept-Encoding: gzip`. No credentials, no privileged access, no special knowledge. The attack is trivially scriptable with `curl` or any HTTP library. The attacker can sustain it indefinitely at negligible cost. The endpoint being disabled by default (`enabled = false`) reduces exposure, but any deployment that enables it is immediately vulnerable. [6](#0-5) 

### Recommendation

1. **Add per-client rate limiting**: Replace or augment the global bucket with per-IP (or per-API-key) buckets so one client cannot exhaust the global budget.
2. **Require authentication**: Gate the endpoint behind an API key or similar credential so abusive clients can be identified and blocked.
3. **Separate the global and per-client limits**: Keep the global cap as a hard ceiling, but add a per-client sub-limit (e.g., 1 req/10s per IP) enforced before the global bucket is consumed.
4. **Add a request timeout**: Ensure the EVM re-execution is bounded by `hiero.mirror.web3.requestTimeout` and that long-running re-executions release server threads promptly. [2](#0-1) 

### Proof of Concept

```bash
# Obtain any valid contract transaction hash from the mirror node REST API
TX_HASH=$(curl -s "https://<mirror-node>/api/v1/contracts/results?limit=1" \
  | jq -r '.results[0].hash')

# Continuously consume the global 1 req/sec opcode budget
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes"
  sleep 1
done
# All concurrent legitimate requests receive HTTP 429 for the duration of the loop.
```

A second terminal running the same request simultaneously will consistently receive `429 Too Many Requests`, confirming complete monopolization of the global budget by the first client. [7](#0-6)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L35-68)
```java
    /**
     * <p>
     * Returns a result containing detailed information for the transaction execution, including all values from the
     * {@code stack}, {@code memory} and {@code storage} and the entire trace of opcodes that were executed during the
     * replay.
     * </p>
     * <p>
     * Note that to provide the output, the transaction needs to be re-executed on the EVM, which may take a significant
     * amount of time to complete if stack and memory information is requested.
     * </p>
     *
     * @param transactionIdOrHash The transaction ID or hash
     * @param stack               Include stack information
     * @param memory              Include memory information
     * @param storage             Include storage information
     * @return {@link OpcodesResponse} containing the result of the transaction execution
     */
    @GetMapping(value = "/{transactionIdOrHash}/opcodes")
    OpcodesResponse getContractOpcodes(
            @PathVariable TransactionIdOrHashParameter transactionIdOrHash,
            @RequestParam(required = false, defaultValue = "true") boolean stack,
            @RequestParam(required = false, defaultValue = "false") boolean memory,
            @RequestParam(required = false, defaultValue = "false") boolean storage,
            @RequestHeader(value = HttpHeaders.ACCEPT_ENCODING) String acceptEncoding) {
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }

        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesProperties.java (L11-11)
```java
    private boolean enabled = false;
```
