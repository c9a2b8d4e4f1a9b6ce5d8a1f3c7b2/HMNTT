### Title
Unauthenticated Global Rate-Limit Monopolization on Opcodes Endpoint Enables Single-Attacker DoS

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint requires no authentication and enforces only a single **global** token-bucket throttle (default: 1 req/sec shared across all callers). A single unauthenticated attacker can continuously consume the entire global budget, monopolizing the endpoint and denying all legitimate users access while sustaining expensive EVM re-executions that exhaust mirror node CPU and memory.

### Finding Description
**Exact code path:**

`OpcodesController.getContractOpcodes()` — `web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java`, lines 52–68:

```java
@GetMapping(value = "/{transactionIdOrHash}/opcodes")
OpcodesResponse getContractOpcodes(...) {
    if (properties.isEnabled()) {
        validateAcceptEncodingHeader(acceptEncoding);   // only checks gzip header
        throttleManager.throttleOpcodeRequest();        // global bucket, no per-client identity
        final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
        return opcodeService.processOpcodeCall(request); // full EVM re-execution
    }
    ...
}
``` [1](#0-0) 

`ThrottleManagerImpl.throttleOpcodeRequest()` uses a single shared `opcodeRateLimitBucket`:

```java
public void throttleOpcodeRequest() {
    if (!opcodeRateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
``` [2](#0-1) 

The bucket is configured globally (one instance for the entire JVM, not per-IP or per-client):

```java
@Bean(name = OPCODE_RATE_LIMIT_BUCKET)
Bucket opcodeRateLimitBucket() {
    long rateLimit = throttleProperties.getOpcodeRequestsPerSecond(); // default: 1
    ...
    return Bucket.builder().addLimit(limit).build(); // single shared bucket
}
``` [3](#0-2) 

Default `opcodeRequestsPerSecond = 1`: [4](#0-3) 

**Root cause:** The throttle is a single global counter with no per-client identity (no IP, no session, no API key). Any unauthenticated caller can continuously consume the one token/second, leaving zero capacity for all other callers. There is no authentication layer, no per-IP limiting, and no Spring Security filter protecting this endpoint.

**Why existing checks fail:**
- `validateAcceptEncodingHeader` only checks for `gzip` — trivially satisfied by any HTTP client.
- `throttleManager.throttleOpcodeRequest()` is a global bucket: once the attacker holds the token, all other callers receive HTTP 429 until the next refill.
- `OpcodesProperties.isEnabled()` is a feature flag, not a security control. [5](#0-4) 

### Impact Explanation
Each accepted request triggers `opcodeService.processOpcodeCall()` → `contractDebugService.processOpcodeCall()`, which re-executes the full transaction on the EVM. The endpoint's own documentation states: *"the transaction needs to be re-executed on the EVM, which may take a significant amount of time to complete if stack and memory information is requested."* [6](#0-5) 

With `stack=true&memory=true&storage=true` (all optional params enabled), each request is maximally expensive. At 1 req/sec sustained, the attacker:
1. Monopolizes the entire global opcode quota — all legitimate users receive HTTP 429.
2. Forces continuous expensive EVM re-executions, consuming CPU, heap, and DB connections.
3. Can sustain this indefinitely from a single IP with no credential or account required.

The mirror node does not participate in consensus, so this does not directly halt transaction confirmation on the Hedera network. However, it fully denies the opcodes debugging endpoint to all users and can degrade overall mirror node performance through resource contention.

### Likelihood Explanation
**Preconditions:** None beyond network access and knowledge that the endpoint exists (it is documented in the public OpenAPI spec at `rest/api/v1/openapi.yml`). [7](#0-6) 

**Attacker capability:** Any HTTP client (curl, Python requests, k6). No account, no key, no token required. The attacker simply sends `GET /api/v1/contracts/results/<any_valid_hash>/opcodes?stack=true&memory=true&storage=true` with `Accept-Encoding: gzip` at 1 req/sec indefinitely.

**Repeatability:** Fully repeatable and automatable. The attacker cannot be identified or blocked by the application because no identity is captured.

### Recommendation
1. **Per-client rate limiting:** Replace or augment the global bucket with a per-IP (or per-API-key) rate limiter (e.g., using `HttpServletRequest.getRemoteAddr()` as the bucket key with bucket4j's `BucketManager`).
2. **Authentication gate:** Require an API key or bearer token for the opcodes endpoint, since it is explicitly a developer/debugging tool, not a public data endpoint.
3. **Concurrency cap:** Add a semaphore or bounded thread pool for EVM re-executions to prevent resource exhaustion even if the rate limiter is bypassed.
4. **Request timeout enforcement:** Ensure `hiero.mirror.web3.requestTimeout` (default 10 000 ms) is enforced per-request so a slow EVM re-execution cannot hold resources indefinitely. [2](#0-1) 

### Proof of Concept
```bash
# Attacker: no credentials, no account needed
# Runs at exactly the global rate limit, monopolizing all capacity

while true; do
  curl -s \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/<valid_tx_hash>/opcodes?stack=true&memory=true&storage=true" \
    -o /dev/null
  sleep 1
done

# Simultaneously, legitimate user receives:
# HTTP 429 Too Many Requests
# {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

The attacker consumes the single global token each second. Every concurrent or subsequent legitimate request is rejected with HTTP 429 for the duration of the attack. No authentication, IP block, or identity check is applied to the attacker.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L35-51)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-68)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** rest/api/v1/openapi.yml (L721-758)
```yaml
        Re-executes a transaction and returns a result containing detailed information for the execution,
        including all values from the {@code stack}, {@code memory} and {@code storage}
        and the entire trace of opcodes that were executed during the replay.

        Note that to provide the output, the transaction needs to be re-executed on the EVM,
        which may take a significant amount of time to complete if stack and memory information is requested.
      operationId: getContractOpcodes
      parameters:
        - $ref: "#/components/parameters/transactionIdOrEthHashPathParam"
        - $ref: "#/components/parameters/stack"
        - $ref: "#/components/parameters/memory"
        - $ref: "#/components/parameters/storage"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/OpcodesResponse"
        400:
          description: Validation error
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Error"
        404:
          description: Transaction or record file not found
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Error"
        429:
          description: Too many requests
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Error"
      tags:
```
