All code claims are verified. Let me check the one remaining detail — whether the endpoint is disabled by default — before rendering the final verdict.

All code claims are verified against the actual source. Every referenced file, function, and line exists and behaves exactly as described. The SECURITY.md exclusion for "Impacts that only require DDoS" does not apply here — this is a single-request amplification attack, not a volumetric distributed flood. The endpoint is disabled by default but is explicitly designed to be enabled in production deployments.

---

## Audit Report

## Title
Missing Gas-Based Throttling in `throttleOpcodeRequest()` Enables Disproportionate Resource Consumption via EVM Replay

## Summary
`throttleOpcodeRequest()` in `ThrottleManagerImpl` enforces only a simple rate limit (default 1 req/sec via `opcodeRateLimitBucket`) with no gas-based throttling. The regular `throttle()` path checks both rate and gas consumption. An unauthenticated caller can target any existing high-gas transaction and trigger a full EVM re-execution with complete per-opcode tracing, generating unbounded opcode trace data and consuming disproportionate CPU and heap memory from a single HTTP request.

## Finding Description

**Entry point:** `OpcodesController.getContractOpcodes()` calls `throttleManager.throttleOpcodeRequest()` at line 61 before dispatching to `opcodeService.processOpcodeCall()`. [1](#0-0) 

**Throttle asymmetry:** `throttleOpcodeRequest()` consumes exactly one token from `opcodeRateLimitBucket` and returns — no gas check. [2](#0-1) 

By contrast, the regular `throttle()` path checks **both** `rateLimitBucket` AND `gasLimitBucket`: [3](#0-2) 

**Default rate:** `opcodeRequestsPerSecond` defaults to 1, and the documentation explicitly acknowledges the endpoint is heavy. [4](#0-3) 

**Gas sourced from stored transaction:** `OpcodeServiceImpl.buildCallServiceParameters()` sets the gas field from the original transaction's stored gas limit — not from the incoming HTTP request — via `getGasLimit()`: [5](#0-4) 

This means the EVM re-execution uses the full original gas limit (up to 15 000 000 gas per `maxGasLimit` config).

**Unbounded opcode accumulation:** `OpcodeActionTracer.tracePostExecution()` is called for every EVM instruction and unconditionally appends a new `Opcode` object — optionally capturing full stack, memory, and storage state — to an `ArrayList` in `OpcodeContext`: [6](#0-5) [7](#0-6) 

Stack, memory, and storage capture are each O(frame state size) per opcode: [8](#0-7) 

**No authentication gate:** The controller has no Spring Security annotations, no role checks, and no API key requirement. [9](#0-8) 

## Impact Explanation
A single opcode trace request targeting a high-gas transaction (e.g., 15 M gas with tight loops) with `stack=true&memory=true&storage=true` causes the mirror node to: (1) re-execute the entire EVM transaction at the original gas limit, (2) allocate and populate one `Opcode` object per EVM instruction — potentially millions — each containing full stack/memory/storage snapshots. This can exhaust JVM heap, trigger GC pressure, cause thread starvation, or produce an OOM kill — all from a single unauthenticated HTTP request. The `gasLimitBucket` that would normally bound this cost is never consulted for opcode requests.

## Likelihood Explanation
Any external user can call `GET /api/v1/contracts/results/{hash}/opcodes?stack=true&memory=true&storage=true`. The attacker only needs to identify one existing high-gas transaction on the network, which is trivially done by querying the mirror node's own REST API for contract results with high `gas_used`. No privileged access, no special tooling, and no brute force is required. The attack is repeatable at 1 req/sec indefinitely. The endpoint must be explicitly enabled (`hiero.mirror.web3.opcode.tracer.enabled=true`), but it is designed for production use and documented as a supported feature.

## Recommendation
1. **Consult `gasLimitBucket` inside `throttleOpcodeRequest()`**: pass the gas limit of the targeted transaction (retrieved from the DB before throttling) and call `gasLimitBucket.tryConsume(throttleProperties.scaleGas(gasLimit))`, mirroring the logic in `throttle()`.
2. **Cap opcode count**: enforce a configurable maximum number of `Opcode` objects accumulated in `OpcodeContext.addOpcodes()`, throwing an exception or truncating when the limit is exceeded.
3. **Require authentication**: gate the endpoint behind an API key or network-level access control, given its explicitly documented heavy resource cost.

## Proof of Concept
```
# 1. Find a high-gas transaction via the mirror node REST API
GET /api/v1/contracts/results?order=desc&limit=1
# Note the transaction_hash with high gas_used (e.g., 14_000_000)

# 2. Replay it with full tracing — single unauthenticated request
GET /api/v1/contracts/results/0x<hash>/opcodes?stack=true&memory=true&storage=true
Accept-Encoding: gzip

# Result: mirror node re-executes the full 14M-gas transaction,
# allocates millions of Opcode objects with stack/memory/storage snapshots,
# exhausting heap and saturating CPU — from one request, at 1 req/sec indefinitely.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L23-27)
```java
@CustomLog
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/contracts/results")
class OpcodesController {
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-65)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L51-56)
```java
    @Override
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L207-209)
```java
    private Long getGasLimit(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
        return ethereumTransaction != null ? ethereumTransaction.getGasLimit() : contractResult.getGasLimit();
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeContext.java (L54-56)
```java
    public void addOpcodes(Opcode opcode) {
        opcodes.add(opcode);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L40-73)
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

    protected final List<String> captureStack(final MessageFrame frame, final OpcodeContext options) {
        if (!options.isStack()) {
            return Collections.emptyList();
        }

        var size = frame.stackSize();
        var stack = new ArrayList<String>(size);
        for (var i = 0; i < size; ++i) {
            var item = frame.getStackItem(size - 1 - i);
            stack.add(hexCache.get(item, Bytes::toHexString));
        }

        return stack;
    }
```
