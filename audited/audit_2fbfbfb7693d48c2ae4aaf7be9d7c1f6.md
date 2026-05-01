### Title
Unbounded EVM Replay Memory Exhaustion via Large-Gas Historical Transaction in Opcodes Endpoint

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint replays any historical transaction stored in the mirror node database without imposing any cap on the number of opcodes generated or the memory consumed during replay. An attacker who previously submitted a high-gas looping contract transaction to the Hedera network (a low-cost, permissionless action) can repeatedly trigger full EVM replays of that transaction, causing the server to allocate unbounded memory for the opcode trace and potentially crash with an out-of-memory error.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` [1](#0-0) 

calls `throttleManager.throttleOpcodeRequest()` (rate-limiting only) then delegates to `opcodeService.processOpcodeCall(request)` with no size or complexity guard.

Inside `OpcodeServiceImpl.processOpcodeCall()`, the gas limit is read directly from the stored transaction record — not from the caller: [2](#0-1) 

The `OpcodeContext` is then pre-allocated with `gas / 3` entries: [3](#0-2) 

For a transaction with Hedera's maximum gas limit (~15 000 000 gas), this pre-allocates ~5 000 000 opcode slots. With `stack=true` (the default), `memory=true`, and `storage=true` query params, each slot carries full EVM stack frames, memory snapshots, and storage diffs — all held in heap before any serialization or gzip compression occurs.

**Root cause:** `OpcodesProperties` contains only an `enabled` flag with no `maxOpcodes`, `maxGas`, or `maxResponseSize` field: [4](#0-3) 

**Why existing checks fail:**

1. **gzip requirement** (`validateAcceptEncodingHeader`) — enforces network compression but the full opcode list is materialized in server heap *before* compression. [5](#0-4) 
2. **`throttleManager.throttleOpcodeRequest()`** — the `ThrottleManager` interface only exposes rate-limiting semantics; it has no knowledge of per-request memory cost. [6](#0-5) 
3. **No calldata/gas cap** — `buildCallServiceParameters` passes the stored gas limit and calldata through unchanged. [7](#0-6) 

### Impact Explanation

A single carefully crafted historical transaction (e.g., a tight EVM loop consuming ~15M gas) can force the mirror node to allocate several gigabytes of heap per request. Repeated concurrent requests — even at a throttled rate — can exhaust JVM heap, triggering `OutOfMemoryError` and crashing the web3 service. This is a complete denial-of-service against all users of the mirror node's web3 API, not just the opcodes endpoint.

### Likelihood Explanation

The precondition is minimal: the attacker needs a Hedera account (free to create) and enough HBAR to pay for one high-gas contract call (fractions of a cent to a few cents). The attack transaction is submitted once and stored permanently in the mirror node database. The attacker can then replay it indefinitely at zero additional on-chain cost. The endpoint is publicly reachable whenever `hiero.mirror.web3.opcode.tracer.enabled=true`. No authentication or special privilege is required.

### Recommendation

1. **Add a `maxGas` cap in `OpcodesProperties`** and reject (or truncate) replay requests whose stored gas limit exceeds it.
2. **Add a `maxOpcodes` cap** — stop collecting opcode entries once the limit is reached and return a partial result with a warning flag.
3. **Stream / paginate the response** rather than materializing the full opcode list in heap before serialization.
4. **Enforce a per-request memory budget** in `OpcodeContext` so that enabling `memory=true` + `storage=true` on a large trace is bounded.

### Proof of Concept

1. Deploy a Solidity contract on Hedera with a tight loop (e.g., `for(uint i=0;i<500000;i++){}`).
2. Call the contract with the maximum allowed gas limit; record the resulting transaction hash `TX_HASH`.
3. Wait for the mirror node to ingest the transaction.
4. Send repeated requests:
   ```
   GET /api/v1/contracts/results/TX_HASH/opcodes?stack=true&memory=true&storage=true
   Accept-Encoding: gzip
   ```
5. Observe JVM heap growth per request; with sufficient concurrency (even within the throttle window), the mirror node process crashes with `OutOfMemoryError`.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L67-67)
```java
            final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L165-175)
```java
        return ContractDebugParameters.builder()
                .block(blockType)
                .callData(getCallDataBytes(ethTransaction, contractResult))
                .ethereumData(getEthereumDataBytes(ethTransaction))
                .consensusTimestamp(consensusTimestamp)
                .gas(getGasLimit(ethTransaction, contractResult))
                .receiver(getReceiverAddress(ethTransaction, contractResult, transactionType))
                .sender(getSenderAddress(contractResult))
                .value(getValue(ethTransaction, contractResult).longValue())
                .build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L207-209)
```java
    private Long getGasLimit(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
        return ethereumTransaction != null ? ethereumTransaction.getGasLimit() : contractResult.getGasLimit();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesProperties.java (L1-12)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.controller;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "hiero.mirror.web3.opcode.tracer")
@Data
public class OpcodesProperties {
    private boolean enabled = false;
}
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManager.java (L7-13)
```java
public interface ThrottleManager {

    void throttle(ContractCallRequest request);

    void throttleOpcodeRequest();

    void restore(long gas);
```
