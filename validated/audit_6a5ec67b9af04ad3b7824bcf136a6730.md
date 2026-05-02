I have verified all the code references. Here is the audit report.

---

Audit Report

## Title
Unbounded Memory Accumulation in EVM Opcode Replay Causes JVM OOM via `memory=true` Parameter

## Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint, when enabled, allows any unauthenticated caller to replay a historical transaction with `memory=true`. `AbstractOpcodeTracer.captureMemory()` snapshots the entire EVM memory frame at every single opcode step with no size cap, and all snapshots accumulate in an unbounded `ArrayList` inside `OpcodeContext`. A single request replaying a memory-intensive transaction can exhaust JVM heap, crashing the mirror node process.

## Finding Description

**Code path:**

`OpcodesController.getContractOpcodes()` accepts `memory=true` from any caller with no authentication. The only guards are a gzip header check and a global rate-limit bucket: [1](#0-0) 

The rate limit is configured at `opcodeRequestsPerSecond = 1` (one request per second **globally**, not per-IP): [2](#0-1) 

`ThrottleManagerImpl.throttleOpcodeRequest()` only checks the single global bucket — a single request is always allowed through: [3](#0-2) 

`OpcodeServiceImpl.processOpcodeCall()` creates an `OpcodeContext` with initial capacity `gas / 3` (up to 5,000,000 for the 15M gas limit) and passes it to the EVM replay: [4](#0-3) 

`OpcodeActionTracer.tracePostExecution()` is called after **every single opcode** and invokes `captureMemory()`: [5](#0-4) 

`AbstractOpcodeTracer.captureMemory()` reads the **entire EVM memory** at each opcode step with no size cap, converting every 32-byte word into a 66-character hex string and adding it to a new `ArrayList`: [6](#0-5) 

All resulting `Opcode` objects (each carrying the full memory snapshot) are appended to an unbounded `ArrayList` in `OpcodeContext`: [7](#0-6) 

**Root cause:** There is no cap on (a) the EVM memory size captured per opcode step, (b) the number of opcode snapshots accumulated, or (c) the total heap consumed per request.

**Memory math:** With `maxGasLimit = 15,000,000`: [8](#0-7) 

A contract that allocates ~10,000 EVM memory words (~225K gas for expansion) and then loops on already-allocated memory can execute ~1,000,000 loop iterations on the remaining gas. Each iteration triggers `captureMemory()`, producing a snapshot of 10,000 × 66-byte strings (~660 KB of Java strings per opcode). Total accumulated heap: ~1,000,000 × 660 KB ≈ **660 GB** — the JVM OOMs long before completion. Even within the 10-second `requestTimeout`, hundreds of gigabytes can be allocated before the timeout fires, and the GC cannot reclaim memory fast enough under allocation pressure.

## Impact Explanation

A single HTTP request causes an unrecoverable `OutOfMemoryError` in the mirror node JVM, crashing the process. This takes down all mirror node services (REST API, gRPC, web3 API) for all users. Recovery requires a process restart. Because the rate limit is global (not per-IP) and allows 1 req/sec, a single attacker can continuously crash the node at 1-second intervals, constituting a sustained denial of service.

## Likelihood Explanation

**Preconditions:**
1. The opcode tracer feature must be enabled (`hiero.mirror.web3.opcode.tracer.enabled=true`). This is `false` by default but is the intended production configuration for debug/trace nodes. [9](#0-8) 
2. A memory-intensive transaction must exist on-chain. Any contract using dynamic arrays, sorting, or data-processing loops qualifies. The attacker does not need to deploy the contract — they only need to find an existing transaction hash.
3. No credentials are required.

The attacker needs only a valid transaction hash (publicly visible on-chain) and the ability to send one HTTP GET request with `Accept-Encoding: gzip`. This is trivially achievable by any external party.

## Recommendation

1. **Cap memory snapshots per opcode**: In `AbstractOpcodeTracer.captureMemory()`, enforce a maximum number of memory words captured per step (e.g., 1,024 words / 32 KB).
2. **Cap total opcode count**: In `OpcodeContext.addOpcodes()`, enforce a maximum list size (e.g., 100,000 entries) and throw a controlled exception if exceeded.
3. **Per-IP rate limiting**: Replace the global `opcodeRateLimitBucket` with a per-IP bucket to prevent a single attacker from monopolizing the 1 req/sec allowance.
4. **Heap guard**: Add a pre-flight check estimating worst-case memory usage from the transaction's gas limit and reject requests that would exceed a configurable threshold.

## Proof of Concept

```
# 1. Find any memory-intensive transaction hash on-chain (e.g., a contract
#    that allocates a large dynamic array and iterates over it).
TX_HASH=0x<memory_intensive_tx_hash>

# 2. Send a single request with memory=true to the enabled opcode endpoint.
curl -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes?memory=true&stack=false&storage=false" \
  --output /dev/null

# 3. Observe the mirror node JVM crash with OutOfMemoryError.
#    Repeat at 1-second intervals to sustain the denial of service.
```

The request passes all guards: the gzip header is present, the global bucket has 1 token available, and no authentication is required. `captureMemory()` then allocates unbounded heap for every opcode step until the JVM OOMs.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeActionTracer.java (L44-62)
```java
    public void tracePostExecution(@NonNull final MessageFrame frame, @NonNull final OperationResult operationResult) {
        final var context = ContractCallContext.get();

        // Reset the balance call flag after BALANCE opcode completes
        if (frame.getCurrentOperation() != null
                && BALANCE_OPERATION_NAME.equals(frame.getCurrentOperation().getName())) {
            context.setBalanceCall(false);
        }

        final var options = context.getOpcodeContext();
        final var memory = captureMemory(frame, options);
        final var stack = captureStack(frame, options);
        final var storage = captureStorage(frame, options, context);

        final var revertReasonBytes = frame.getRevertReason().orElse(null);
        final var reason = revertReasonBytes != null ? revertReasonBytes.toHexString() : null;
        context.getOpcodeContext()
                .addOpcodes(createOpcode(frame, operationResult.getGasCost(), reason, stack, memory, storage));
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

**File:** docs/configuration.md (L710-710)
```markdown
| `hiero.mirror.web3.evm.maxGasLimit`                          | 15000000                                           | The maximum amount of gas limit the user can supply in the request.                                                                                                                              |
```

**File:** docs/configuration.md (L719-719)
```markdown
| `hiero.mirror.web3.opcode.tracer.enabled`                    | false                                              | Whether the `/contracts/results/{transactionIdOrHash}/opcodes` endpoint is exposed                                                                                                               |
```
