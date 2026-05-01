### Title
Unbounded In-Memory Opcode Response Buffering Enables Heap Exhaustion DoS via Trivially-Satisfied gzip Check

### Summary
`getContractOpcodes()` requires `Accept-Encoding: gzip` as a size-mitigation measure, but this check is trivially satisfied by any attacker and does not prevent the full `OpcodesResponse` object graph from being materialized in JVM heap before serialization. The `OpcodeContext.opcodes` list is an unbounded `ArrayList` with no maximum entry cap, and the opcode throttle limits only request rate (default: 1 req/sec), not response size. A single request referencing a high-gas historical transaction with `stack=true&memory=true&storage=true` can exhaust heap and crash the JVM.

### Finding Description

**Code path:**

`OpcodesController.getContractOpcodes()` (lines 52–68) performs two checks before processing:

1. `validateAcceptEncodingHeader(acceptEncoding)` — rejects requests lacking `gzip` in `Accept-Encoding`. The code comment explicitly acknowledges the response is "huge." However, this check only gates on a header value the attacker fully controls; any attacker simply sends `Accept-Encoding: gzip`. It does not prevent heap allocation.

2. `throttleManager.throttleOpcodeRequest()` — implemented in `ThrottleManagerImpl` (lines 52–55) as a token-bucket check against `opcodeRateLimitBucket`. Default capacity is `opcodeRequestsPerSecond = 1` (ThrottleProperties line 29). This limits throughput to 1 req/sec but places zero constraint on the size of any individual response.

After both checks pass, `OpcodeServiceImpl.processOpcodeCall()` (lines 64–74) constructs an `OpcodeContext` whose `opcodes` field is an `ArrayList` initialized with capacity `gas/3` (line 67) — a hint, not a cap. `OpcodeContext.addOpcodes()` (line 54) appends without any bound check. The EVM re-executes the full historical transaction, appending one `Opcode` entry per executed instruction. With `memory=true`, each entry carries a full snapshot of EVM memory at that step; with `stack=true` (the default), each carries up to 1024×32 bytes of stack; with `storage=true`, all modified storage slots. The entire list is returned as a Java object and serialized to JSON in-process before any compression occurs.

**Root cause:** The failed assumption is that requiring `Accept-Encoding: gzip` prevents large responses from being buffered. It does not — it only affects the transport encoding. The actual heap allocation happens unconditionally during EVM re-execution and response construction, with no size limit at any layer.

### Impact Explanation

A single request against a high-gas historical transaction (Hedera allows up to 15 M gas; PUSH1 costs 3 gas, yielding up to ~5 M opcodes per transaction) with all three trace options enabled can produce hundreds of MB to multiple GB of live Java objects in heap. This causes `OutOfMemoryError`, crashing the JVM and taking down the entire web3 API service. All concurrent requests are dropped. The impact is a complete denial-of-service of the web3 API node. Note: the mirror node web3 service does not participate in consensus; crashing it does not halt on-chain transaction confirmation, but it does eliminate all web3 API availability for that node.

### Likelihood Explanation

Preconditions: (1) the operator has set `hiero.mirror.web3.opcode.tracer.enabled=true` (disabled by default, but required for the endpoint to function at all); (2) the attacker knows or can discover a historical transaction hash with high gas consumption (publicly visible on-chain). Both are realistic for any production deployment of this feature. The exploit requires no credentials, no special protocol knowledge, and no prior access — only an HTTP client that includes `Accept-Encoding: gzip`. The 1 req/sec throttle means a single attacker connection is sufficient; no flood is needed.

### Recommendation

1. **Enforce a hard opcode count cap** in `OpcodeContext.addOpcodes()`: throw or truncate when `opcodes.size()` exceeds a configurable maximum (e.g., 100,000 entries).
2. **Add a configurable `maxResponseBytes` property** to `OpcodesProperties` and abort processing when the estimated serialized size exceeds it.
3. **Stream the response** using `StreamingResponseBody` or reactive types so the JVM never holds the full object graph in heap simultaneously.
4. **Enforce a gas ceiling** specific to opcode tracing requests, separate from the general gas throttle, to bound worst-case opcode count before execution begins.

### Proof of Concept

```
# Step 1: Identify a high-gas historical transaction hash on the network
TX_HASH=0x<high_gas_tx_hash>

# Step 2: Send request — trivially satisfies the gzip check, enables all trace options
curl -v \
  -H "Accept-Encoding: gzip" \
  "https://<mirror-node-host>/api/v1/contracts/results/${TX_HASH}/opcodes?stack=true&memory=true&storage=true"

# Result: server allocates unbounded heap for all per-opcode stack/memory/storage
# snapshots; for a ~15M gas transaction this can exceed available heap,
# triggering OutOfMemoryError and JVM crash, taking down the web3 API service.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L75-86)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeContext.java (L47-56)
```java
    public OpcodeContext(final OpcodeRequest opcodeRequest, final int opcodesSize) {
        this.stack = opcodeRequest.isStack();
        this.memory = opcodeRequest.isMemory();
        this.storage = opcodeRequest.isStorage();
        this.opcodes = new ArrayList<>(opcodesSize);
    }

    public void addOpcodes(Opcode opcode) {
        opcodes.add(opcode);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L64-74)
```java
    public OpcodesResponse processOpcodeCall(@NonNull OpcodeRequest opcodeRequest) {
        return ContractCallContext.run(ctx -> {
            final var params = buildCallServiceParameters(opcodeRequest.getTransactionIdOrHashParameter());
            final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);

            ctx.setOpcodeContext(opcodeContext);

            final OpcodesProcessingResult result = contractDebugService.processOpcodeCall(params, opcodeContext);
            return buildOpcodesResponse(result);
        });
    }
```
