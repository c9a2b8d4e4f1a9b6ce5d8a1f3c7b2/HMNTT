All code references have been verified against the actual source. Here is the assessment:

---

Audit Report

## Title
Unbounded EVM Replay Memory Exhaustion via Large-Gas Historical Transaction in Opcodes Endpoint

## Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint replays historical transactions without imposing any cap on the gas limit used for replay or the number of opcode entries accumulated in memory. The gas value is read directly from the stored transaction record and used to pre-allocate an `ArrayList` for opcode collection, with no upper bound enforced anywhere in the call chain.

## Finding Description

**Verified code path:**

`OpcodesController.getContractOpcodes()` calls `throttleManager.throttleOpcodeRequest()` (count-only rate limiting) then delegates to `opcodeService.processOpcodeCall(request)` with no size or complexity guard. [1](#0-0) 

Inside `OpcodeServiceImpl.processOpcodeCall()`, the gas limit is read from the stored transaction record via `buildCallServiceParameters`, then used directly as the initial capacity of the opcode list:

```java
final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);
``` [2](#0-1) 

`OpcodeContext`'s constructor allocates an `ArrayList` with that initial capacity:

```java
this.opcodes = new ArrayList<>(opcodesSize);
``` [3](#0-2) 

The gas limit is read directly from the stored `EthereumTransaction` or `ContractResult` record, with no cap applied:

```java
private Long getGasLimit(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
    return ethereumTransaction != null ? ethereumTransaction.getGasLimit() : contractResult.getGasLimit();
}
``` [4](#0-3) 

`OpcodesProperties` contains only an `enabled` flag — no `maxOpcodes`, `maxGas`, or `maxResponseSize`: [5](#0-4) 

**Why existing mitigations are insufficient:**

1. **`validateAcceptEncodingHeader`** — enforces gzip on the network response, but the full opcode list is materialized in JVM heap *before* any serialization or compression occurs. [6](#0-5) 

2. **`throttleOpcodeRequest()`** — only enforces a request-count bucket (default: 1 RPS). It has no knowledge of per-request gas or memory cost. [7](#0-6) 

3. **`requestTimeout` (10 s default)** — enforced only via a Hibernate `StatementInspector` that checks elapsed time on database queries. It does **not** interrupt the EVM execution loop itself. [8](#0-7) 

4. **`maxGasLimit` in `EvmProperties`** — this cap (default 15 000 000) applies to the `/contracts/call` endpoint via `validateContractMaxGasLimit`. It is **not** applied in the opcodes replay path, which reads the gas from the historical record. [9](#0-8) 

## Impact Explanation

A single historical transaction with a high gas limit (up to the network maximum of ~15 000 000 gas) causes the server to:

1. Pre-allocate an `ArrayList` of ~5 000 000 slots (≈40 MB for the reference array alone).
2. Populate it with `Opcode` objects during EVM replay. With `stack=true`, `memory=true`, and `storage=true`, each object carries full EVM stack frames, memory word snapshots, and storage diffs — all held in heap simultaneously before serialization.

Even at the default 1 RPS throttle, a single in-flight request for a maximum-gas looping contract can hold hundreds of megabytes to gigabytes of heap. Multiple concurrent requests (possible if the throttle is raised or bypassed by multiple clients) can exhaust JVM heap and trigger `OutOfMemoryError`, crashing the web3 service for all users.

## Likelihood Explanation

**Preconditions:**
- The operator must have set `hiero.mirror.web3.opcode.tracer.enabled=true` (disabled by default). [10](#0-9) 
- The attacker needs one historical high-gas contract transaction stored in the mirror node database (a one-time, low-cost on-chain action).

Once the endpoint is enabled and the seed transaction exists, the attacker can replay it indefinitely at zero additional on-chain cost. No authentication is required. The default 1 RPS throttle limits the rate but does not prevent a single request from consuming large amounts of heap, and does not prevent sustained pressure over time.

## Recommendation

1. **Cap gas for replay**: In `OpcodeServiceImpl.buildCallServiceParameters`, clamp the gas value to `evmProperties.getMaxGasLimit()` before passing it to `ContractDebugParameters` and `OpcodeContext`.
2. **Add `maxOpcodes` to `OpcodesProperties`**: Introduce a configurable hard limit on the number of opcode entries that can be accumulated per request. Abort or truncate replay when the limit is reached.
3. **Apply the request timeout to EVM execution**: The `requestTimeout` should interrupt the EVM replay loop, not only database queries.
4. **Gas-aware throttling**: Extend `throttleOpcodeRequest()` to consume tokens proportional to the gas limit of the replayed transaction, similar to how `throttle(ContractCallRequest)` consumes from the `gasLimitBucket`.

## Proof of Concept

1. Submit a Hedera contract call transaction that executes a tight EVM loop consuming close to 15 000 000 gas. Record the transaction hash.
2. Enable the opcodes endpoint on a mirror node: `hiero.mirror.web3.opcode.tracer.enabled=true`.
3. Send the following request repeatedly (or concurrently from multiple clients):

```
GET /api/v1/contracts/results/<tx_hash>/opcodes?stack=true&memory=true&storage=true
Accept-Encoding: gzip
```

4. Observe JVM heap growth via JMX or GC logs. With a maximum-gas looping contract, each request materializes millions of `Opcode` objects in heap before any response is written. Sustained requests will exhaust the JVM heap and produce `OutOfMemoryError`.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L67-67)
```java
            final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L207-209)
```java
    private Long getGasLimit(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
        return ethereumTransaction != null ? ethereumTransaction.getGasLimit() : contractResult.getGasLimit();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeContext.java (L47-52)
```java
    public OpcodeContext(final OpcodeRequest opcodeRequest, final int opcodesSize) {
        this.stack = opcodeRequest.isStack();
        this.memory = opcodeRequest.isMemory();
        this.storage = opcodeRequest.isStorage();
        this.opcodes = new ArrayList<>(opcodesSize);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesProperties.java (L10-12)
```java
public class OpcodesProperties {
    private boolean enabled = false;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-46)
```java
    StatementInspector statementInspector() {
        long timeout = web3Properties.getRequestTimeout().toMillis();
        return sql -> {
            if (!ContractCallContext.isInitialized()) {
                return sql;
            }

            var startTime = ContractCallContext.get().getStartTime();
            long elapsed = System.currentTimeMillis() - startTime;

            if (elapsed >= timeout) {
                throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
            }

            return sql;
        };
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L92-97)
```java
    private void validateContractMaxGasLimit(ContractCallRequest request) {
        if (request.getGas() > evmProperties.getMaxGasLimit()) {
            throw new InvalidParametersException(
                    "gas field must be less than or equal to %d".formatted(evmProperties.getMaxGasLimit()));
        }
    }
```

**File:** docs/configuration.md (L719-719)
```markdown
| `hiero.mirror.web3.opcode.tracer.enabled`                    | false                                              | Whether the `/contracts/results/{transactionIdOrHash}/opcodes` endpoint is exposed                                                                                                               |
```
