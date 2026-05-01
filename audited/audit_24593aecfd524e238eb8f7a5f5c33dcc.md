### Title
Unbounded In-Memory Accumulation of EVM Memory Snapshots in `getContractOpcodes()` Leads to Node OOM

### Summary
When `memory=true` is passed to `getContractOpcodes()`, the tracer captures a full snapshot of the entire EVM memory at every single opcode step and accumulates all snapshots in an unbounded `ArrayList` before serialization. No cap exists on the number of opcodes stored, the size of each memory snapshot, or the total response payload. An unprivileged user can trigger this against any existing high-gas historical transaction, causing the mirror node to exhaust its heap and crash.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` accepts `memory=true` from any caller with no authentication: [1](#0-0) 

The only guards are: (1) a gzip header check (reduces network bytes, not server-side heap), and (2) a token-bucket rate limiter at 1 req/sec: [2](#0-1) 

The rate limiter is **not** a concurrency limiter. `tryConsume(1)` is non-blocking; after 1 second the bucket refills, so if a request takes 60 s to process, up to ~60 concurrent memory-exhausting requests can be in flight simultaneously.

`OpcodeServiceImpl.processOpcodeCall()` initialises the opcode list with an initial capacity hint of `gas/3` (up to 5 million for a 15 M-gas transaction) but imposes **no hard upper bound**: [3](#0-2) 

`OpcodeContext.addOpcodes()` appends to an unbounded `ArrayList` with no size check: [4](#0-3) 

`AbstractOpcodeTracer.captureMemory()` reads the **entire** EVM memory at every opcode step with no size limit: [5](#0-4) 

`frame.memoryWordSize()` returns the current number of 32-byte words in the EVM memory frame. For a transaction that has expanded memory to W words and then executes N more cheap opcodes (e.g., `ADD` at 3 gas each), the total heap consumed is proportional to `N × W × 66 bytes` (each word is serialised as a `"0x"` + 64-hex-char `String`).

**Root cause:** The failed assumption is that gas cost alone bounds the output size. Gas bounds the *total work* done by the EVM, but once memory is expanded it stays expanded for the rest of the call frame. Cheap opcodes (3 gas each) executed after a large memory expansion each trigger a full memory snapshot. With 15 M gas, ~1 M cheap opcodes after a ~1,000-word expansion produces ~66 GB of `String` objects before any serialisation.

**Why existing checks fail:**

- `validateAcceptEncodingHeader`: enforces gzip on the *response wire*, not on the in-process heap.
- `throttleOpcodeRequest()`: token-bucket rate limit of 1/s; does not bound concurrency or per-request heap.
- `maxGasLimit = 15_000_000`: caps the gas for *new* contract calls, but the replay uses the gas limit stored in the historical `ContractResult`/`EthereumTransaction` record, which can be up to 15 M. [6](#0-5) 

### Impact Explanation
A single well-chosen request can allocate tens of gigabytes of heap inside the JVM before the response is serialised. This causes an `OutOfMemoryError`, crashing the web3 mirror-node process. Because the rate limiter refills every second and does not track in-flight requests, a sustained stream of such requests (one per second) keeps the node permanently OOM-cycling. This directly disrupts all contract-call and opcode-trace services hosted by the node, satisfying the "≥30% of network processing nodes" DoS threshold when multiple mirror nodes are targeted.

### Likelihood Explanation
The endpoint requires only that `hiero.mirror.web3.opcode.tracer.enabled=true` (operators enable it for debugging). No account, API key, or privileged role is needed. The attacker only needs to identify one historical transaction with high gas usage and significant memory expansion — such transactions are publicly visible on-chain (e.g., complex DeFi deployments). The exploit is fully repeatable at 1 req/s per attacker IP, and multiple IPs can be used simultaneously since the bucket is global but non-concurrent.

### Recommendation
1. **Hard cap on opcode count**: In `OpcodeContext.addOpcodes()`, throw or truncate once `opcodes.size()` exceeds a configurable limit (e.g., 100,000).
2. **Hard cap on memory snapshot size**: In `captureMemory()`, return an empty list (or a truncated list) if `frame.memoryWordSize()` exceeds a configurable threshold (e.g., 1,024 words).
3. **Concurrency limit**: Replace or augment the token-bucket with a semaphore so at most N (e.g., 2) opcode-trace requests execute concurrently.
4. **Response size budget**: Track total bytes accumulated across all `Opcode` objects during a single trace and abort with HTTP 413 once a budget (e.g., 50 MB uncompressed) is exceeded.

### Proof of Concept

**Preconditions:**
- Mirror node has `hiero.mirror.web3.opcode.tracer.enabled=true`.
- A historical transaction `TX_HASH` exists whose contract expanded EVM memory to ≥1,000 words and then executed ≥500,000 cheap opcodes (e.g., a loop-heavy contract with 15 M gas).

**Steps:**
```
# Step 1 – identify a high-gas historical transaction hash from the public mirror REST API
TX_HASH=<hash of a 15M-gas transaction with heavy MSTORE usage>

# Step 2 – send the exploit request (no authentication required)
curl -v \
  -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes?memory=true"
```

**Result:** The JVM heap fills with `String` objects representing per-opcode memory snapshots. The node throws `java.lang.OutOfMemoryError: Java heap space`, the Spring Boot process crashes, and the mirror node becomes unavailable until restarted. Repeating the request once per second prevents recovery.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L64-73)
```java
    public OpcodesResponse processOpcodeCall(@NonNull OpcodeRequest opcodeRequest) {
        return ContractCallContext.run(ctx -> {
            final var params = buildCallServiceParameters(opcodeRequest.getTransactionIdOrHashParameter());
            final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);

            ctx.setOpcodeContext(opcodeContext);

            final OpcodesProcessingResult result = contractDebugService.processOpcodeCall(params, opcodeContext);
            return buildOpcodesResponse(result);
        });
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L207-209)
```java
    private Long getGasLimit(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
        return ethereumTransaction != null ? ethereumTransaction.getGasLimit() : contractResult.getGasLimit();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeContext.java (L54-56)
```java
    public void addOpcodes(Opcode opcode) {
        opcodes.add(opcode);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L40-58)
```java
    protected final List<String> captureMemory(final MessageFrame frame, final OpcodeContext options) {
        if (!options.isMemory()) {
            return Collections.emptyList();
        }
        var size = frame.memoryWordSize();
        var hexMemoryEntries = new ArrayList<String>(size);

        final var wordSize = 32;
        final var memory = frame.readMutableMemory(0L, (long) wordSize * size).toArrayUnsafe();
        final var hex = HexFormat.of();

        for (var i = 0; i < size; i++) {
            var startIndex = i * wordSize;
            final var result = HEX_PREFIX + hex.formatHex(memory, startIndex, startIndex + wordSize);
            hexMemoryEntries.add(result);
        }

        return hexMemoryEntries;
    }
```
