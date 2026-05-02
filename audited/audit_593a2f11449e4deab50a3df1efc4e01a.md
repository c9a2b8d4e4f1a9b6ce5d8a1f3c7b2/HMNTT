### Title
Unbounded Storage Trace Response Causes Server-Side Memory Exhaustion in `getContractOpcodes()`

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes?storage=true` endpoint, accessible to any unauthenticated user, re-executes a historical transaction and attaches the full cumulative storage-access map to **every single opcode entry** in the response. There is no cap on the number of opcodes, the number of storage slots, or the total response size. The mandatory `Accept-Encoding: gzip` header mitigates network bandwidth but does nothing to prevent the server from constructing an arbitrarily large in-memory object graph before serialization, enabling server-side heap exhaustion with a single well-chosen request.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` at [1](#0-0)  accepts `storage=true` from any caller with no authentication. It calls `throttleManager.throttleOpcodeRequest()` [2](#0-1)  which only enforces a **global** token-bucket rate of `opcodeRequestsPerSecond = 1` (default). [3](#0-2) 

`ThrottleManagerImpl.throttleOpcodeRequest()` consumes one token from a single shared bucket — there is no per-IP or per-user isolation. [4](#0-3) 

During EVM replay, `AbstractOpcodeTracer.captureStorage()` is invoked on **every opcode** via `tracePostExecution`. Each invocation allocates a **new `TreeMap<String, String>`** containing all storage slots accessed so far in the transaction, with no upper bound on map size. [5](#0-4) 

This map is embedded into every `Opcode` object appended to the unbounded `ArrayList` in `OpcodeContext`. [6](#0-5) 

The final `OpcodesResponse` is built from this list with no truncation or size check. [7](#0-6) 

**Root cause:** The storage snapshot is O(M) per opcode and is replicated N times (once per opcode), yielding O(N × M) total heap allocation before any serialization or compression occurs. The gzip enforcement comment explicitly acknowledges the response is "huge" but only addresses network latency, not server-side memory. [8](#0-7) 

**Failed assumption:** The design assumes gzip compression is sufficient protection. It is not — compression happens after the full object graph is materialized in the JVM heap.

### Impact Explanation

For a transaction consuming 15 M gas:
- Maximum unique cold `SSTORE` operations: ~7,142 (at 2,100 gas each)
- Cheap opcodes (e.g., `ADD` at 3 gas) can produce up to ~5 M opcode entries

A realistic worst-case (e.g., 50,000 opcodes × 500 storage slots) produces 25 M `TreeMap` entries, each holding two ~66-byte hex strings, totalling several gigabytes of heap before Jackson serializes the response. This can trigger JVM `OutOfMemoryError`, crash the web3 service pod, or cause GC pauses that degrade all concurrent users. Even at the 1 req/sec global rate, a single attacker can sustain continuous heap pressure.

### Likelihood Explanation

- No authentication is required; any internet user can call the endpoint.
- The attacker only needs to know the hash of one historical high-gas transaction (publicly visible on-chain).
- The `Accept-Encoding: gzip` header is trivially supplied by any HTTP client (`curl -H "Accept-Encoding: gzip" ...`).
- The global rate limit of 1 req/sec does not prevent a single request from exhausting heap; it only limits request frequency.
- The feature flag (`enabled = false` by default) reduces exposure in default deployments, but any operator who enables the feature is immediately exposed.

### Recommendation

1. **Cap the number of opcodes returned**: Introduce a configurable `maxOpcodes` limit in `OpcodesProperties` and truncate `OpcodeContext.opcodes` when the limit is reached.
2. **Cap storage slots per opcode**: In `captureStorage()`, limit the `TreeMap` to a configurable maximum (e.g., 1,000 entries) and document the truncation.
3. **Per-IP/per-user rate limiting**: Replace the single global bucket with per-source-IP rate limiting so one attacker cannot monopolize the 1 req/sec allowance.
4. **Stream the response**: Use `StreamingResponseBody` or chunked JSON serialization to avoid materializing the entire response in heap before writing.
5. **Add a response-size circuit breaker**: Track estimated byte size during opcode accumulation and abort with HTTP 413 if a threshold is exceeded.

### Proof of Concept

```bash
# 1. Identify a historical high-gas transaction hash from a public explorer
TX_HASH="0x<hash_of_heavy_sstore_transaction>"

# 2. Send the request with storage=true (no auth required)
curl -v \
  -H "Accept-Encoding: gzip" \
  "https://<mirror-node-web3>/api/v1/contracts/results/${TX_HASH}/opcodes?storage=true&stack=false&memory=false" \
  --output /dev/null

# 3. Observe: server JVM heap spikes to several GB during response construction.
#    Repeat at 1 req/sec to sustain pressure:
while true; do
  curl -s -H "Accept-Encoding: gzip" \
    "https://<mirror-node-web3>/api/v1/contracts/results/${TX_HASH}/opcodes?storage=true" \
    -o /dev/null
  sleep 1
done
# Result: OOM / GC thrashing / service crash
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-65)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L70-86)
```java
    /**
     * Validates if the "Accept-Encoding" header contains "gzip". This is necessary because the response
     * from this endpoint is huge and without compression this will result in big network latency.
     * @param acceptEncodingHeader the passed "Accept-Encoding" header from the request
     */
    private void validateAcceptEncodingHeader(String acceptEncodingHeader) {
        if (acceptEncodingHeader == null || !acceptEncodingHeader.toLowerCase().contains("gzip")) {
            throw HttpClientErrorException.create(
                    MISSING_GZIP_HEADER_MESSAGE,
                    HttpStatus.NOT_ACCEPTABLE,
                    HttpStatus.NOT_ACCEPTABLE.getReasonPhrase(),
                    null, // headers
                    null, // body
                    null // charset
                    );
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L29-29)
```java
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-55)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L75-129)
```java
    protected Map<String, String> captureStorage(
            final MessageFrame frame, final OpcodeContext options, final ContractCallContext context) {
        if (!options.isStorage()) {
            return Collections.emptyMap();
        }

        try {
            if (context.getOpcodeContext().getRootProxyWorldUpdater() == null) {

                var worldUpdater = frame.getWorldUpdater();
                var parent = worldUpdater.parentUpdater().orElse(null);
                while (parent != null) {
                    worldUpdater = parent;
                    parent = worldUpdater.parentUpdater().orElse(null);
                }

                if (!(worldUpdater instanceof RootProxyWorldUpdater rootProxyWorldUpdater)) {
                    // The storage updates are kept only in the RootProxyWorldUpdater.
                    // If we don't have one -> something unexpected happened and an attempt to
                    // get the storage changes from a ProxyWorldUpdater would result in a
                    // NullPointerException, so in this case just return an empty map.
                    return Collections.emptyMap();
                }

                context.getOpcodeContext().setRootProxyWorldUpdater(rootProxyWorldUpdater);
            }

            final var rootProxyWorldUpdater = context.getOpcodeContext().getRootProxyWorldUpdater();
            final var updates = rootProxyWorldUpdater
                    .getEvmFrameState()
                    .getTxStorageUsage(true)
                    .accesses();

            if (updates.isEmpty()) {
                return Collections.emptyMap();
            }

            final var result = new TreeMap<String, String>();
            for (final var storageAccesses : updates) {
                for (final var access : storageAccesses.accesses()) {
                    final var key = hexCache.get(access.key(), Bytes::toHexString);
                    if (!result.containsKey(key)) {
                        final var value = access.writtenValue() != null
                                ? hexCache.get(access.writtenValue(), Bytes::toHexString)
                                : hexCache.get(access.value(), Bytes::toHexString);
                        result.put(key, value);
                    }
                }
            }
            return result;

        } catch (final ModificationNotAllowedException e) {
            return Collections.emptyMap();
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeContext.java (L54-56)
```java
    public void addOpcodes(Opcode opcode) {
        opcodes.add(opcode);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L141-149)
```java
        final var opcodes = result.opcodes() != null ? result.opcodes() : new ArrayList<Opcode>();

        return new OpcodesResponse()
                .address(address)
                .contractId(contractId)
                .failed(txnResult == null || !txnResult.isSuccessful())
                .gas(txnResult != null ? txnResult.gasUsed() : 0L)
                .opcodes(opcodes)
                .returnValue(returnValue);
```
