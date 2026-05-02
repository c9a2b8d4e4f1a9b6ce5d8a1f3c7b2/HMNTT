All four technical claims are verified against the actual source code. Here is the analysis:

**Claim 1 — `ContractDebugService.validateResult()` swallows the exception:** Confirmed at lines 62–72. The `catch (MirrorEvmTransactionException e)` block logs a warning but never re-throws. [1](#0-0) 

**Claim 2 — `doProcessCall()` status stays `"SUCCESS"`:** Confirmed. `status` is initialized to `"SUCCESS"` at line 112 and is only updated inside the `catch (MirrorEvmTransactionException e)` block at line 125, which is never reached when the override swallows the exception. [2](#0-1) 

**Claim 3 — `handleFailedResult()` returns instead of throwing in opcode context:** Confirmed at lines 147–159. When `opcodeContext != null`, the method returns a failed `EvmTransactionResult` instead of throwing, so `execute()` never throws and `result` is non-null. [3](#0-2) 

**Claim 4 — `isSuccessful()` correctly returns `false` for non-SUCCESS codes:** Confirmed. [4](#0-3) 

**Metrics update with wrong tag:** `updateMetrics` is called with the `status` string directly as a tag, so `"SUCCESS"` is recorded for every reverted debug call. [5](#0-4) 

---

## Audit Report

## Title
`ContractDebugService.validateResult()` Swallows Exception, Causing Reverted Transactions to Be Metrically Recorded as SUCCESS

## Summary
`ContractDebugService` overrides `validateResult()` and silently swallows the `MirrorEvmTransactionException` thrown by the parent for reverted transactions. Because `doProcessCall()` only updates `status` away from `"SUCCESS"` inside the `catch (MirrorEvmTransactionException e)` block — which is never reached when the exception is swallowed inside `validateResult()` — `updateMetrics()` is called with `status = "SUCCESS"` for every reverted transaction processed through the debug path.

## Finding Description
**Root cause — `ContractDebugService.validateResult()` (lines 62–72):** [1](#0-0) 

```java
@Override
protected void validateResult(final EvmTransactionResult txnResult, final CallServiceParameters params) {
    try {
        super.validateResult(txnResult, params);   // throws MirrorEvmTransactionException for reverts
    } catch (MirrorEvmTransactionException e) {
        log.warn(...);   // exception swallowed — never re-thrown
    }
}
```

The parent `ContractCallService.validateResult()` throws `MirrorEvmTransactionException` whenever `txnResult.isSuccessful()` is `false`: [6](#0-5) 

**Execution flow in `doProcessCall()` (lines 109–138):** [2](#0-1) 

```
status = "SUCCESS"                          // line 112
result = execute(params, estimatedGas)      // returns failed EvmTransactionResult (not thrown)
validateResult(result, params)              // exception swallowed inside override
// catch(MirrorEvmTransactionException) NEVER reached → status stays "SUCCESS"
// finally: result != null → updateMetrics(..., "SUCCESS")
```

**Enabler — `TransactionExecutionService.handleFailedResult()` (lines 147–159):** [3](#0-2) 

When an opcode context is active (debug path), the method **returns** the failed `EvmTransactionResult` instead of throwing, so `execute()` itself does not throw and `result` is non-null with a non-SUCCESS `responseCodeEnum`.

## Impact Explanation
Every call through `ContractDebugService.processOpcodeCall()` that results in a reverted EVM transaction increments the `hiero.mirror.web3.evm.invocation` counter and the `hiero.mirror.web3.evm.gas.used` counter with `TAG_STATUS = "SUCCESS"`. [5](#0-4) 

Operators and automated alerting systems relying on these Micrometer metrics to detect failure rates will see an artificially inflated success rate, masking real revert activity. This constitutes incorrect status records exported via the metrics pipeline (Prometheus/Micrometer scrape endpoints).

## Likelihood Explanation
The `processOpcodeCall()` endpoint is a read-only historical replay operation requiring no privileged credentials. Any user who can reach the mirror node's web3 API can submit a `ContractDebugParameters` request referencing a known historically-reverted transaction. The trigger is fully deterministic and repeatable: every such request will produce the incorrect SUCCESS metric. No special account, token, or on-chain state is required. [7](#0-6) 

## Recommendation
In `ContractDebugService.validateResult()`, re-throw the caught exception after logging, so that `doProcessCall()`'s `catch (MirrorEvmTransactionException e)` block is reached and `status` is updated correctly before `updateMetrics()` is called:

```java
@Override
protected void validateResult(final EvmTransactionResult txnResult, final CallServiceParameters params) {
    try {
        super.validateResult(txnResult, params);
    } catch (MirrorEvmTransactionException e) {
        log.warn(
            "Transaction failed with status: {}, detail: {}, revertReason: {}",
            txnResult.responseCodeEnum(),
            e.getDetail(),
            e.getData());
        throw e;  // re-throw so doProcessCall() records the correct status
    }
}
```

Alternatively, `doProcessCall()` could inspect `result.isSuccessful()` directly in the `finally` block to determine the correct metric status, independent of whether an exception was thrown.

## Proof of Concept
1. Identify any historically-reverted transaction on the mirror node (any transaction whose EVM execution resulted in a non-SUCCESS `responseCodeEnum`).
2. Submit a `ContractDebugParameters` request to `processOpcodeCall()` referencing that transaction's consensus timestamp.
3. `TransactionExecutionService.handleFailedResult()` returns a failed `EvmTransactionResult` (does not throw) because `opcodeContext != null`.
4. `ContractDebugService.validateResult()` catches and swallows the `MirrorEvmTransactionException` from the parent.
5. `doProcessCall()`'s `catch (MirrorEvmTransactionException e)` block is never reached; `status` remains `"SUCCESS"`.
6. `updateMetrics(params, result.gasUsed(), 1, "SUCCESS")` is called in the `finally` block.
7. Scraping the Prometheus endpoint confirms `hiero_mirror_web3_evm_invocation_total{status="SUCCESS"}` and `hiero_mirror_web3_evm_gas_used_total{status="SUCCESS"}` were incremented for the reverted transaction.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractDebugService.java (L48-59)
```java
    public OpcodesProcessingResult processOpcodeCall(
            final @Valid ContractDebugParameters params, final OpcodeContext opcodeContext) {
        ContractCallContext ctx = ContractCallContext.get();
        ctx.setTimestamp(Optional.of(params.getConsensusTimestamp() - 1));
        ctx.setOpcodeContext(opcodeContext);
        ctx.getOpcodeContext()
                .setActions(contractActionRepository.findFailedSystemActionsByConsensusTimestamp(
                        params.getConsensusTimestamp()));
        final var ethCallTxnResult = callContract(params, ctx);
        return new OpcodesProcessingResult(
                ethCallTxnResult, params.getReceiver(), ctx.getOpcodeContext().getOpcodes());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractDebugService.java (L61-72)
```java
    @Override
    protected void validateResult(final EvmTransactionResult txnResult, final CallServiceParameters params) {
        try {
            super.validateResult(txnResult, params);
        } catch (MirrorEvmTransactionException e) {
            log.warn(
                    "Transaction failed with status: {}, detail: {}, revertReason: {}",
                    txnResult.responseCodeEnum(),
                    e.getDetail(),
                    e.getData());
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L109-138)
```java
    protected final EvmTransactionResult doProcessCall(
            CallServiceParameters params, long estimatedGas, boolean estimate) throws MirrorEvmTransactionException {
        EvmTransactionResult result = null;
        var status = ResponseCodeEnum.SUCCESS.toString();

        try {
            result = transactionExecutionService.execute(params, estimatedGas);

            if (!estimate) {
                validateResult(result, params);
            }
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw new MirrorEvmTransactionException(e.getMessage(), EMPTY);
        } catch (MirrorEvmTransactionException e) {
            // This result is needed in case of exception to be still able to call restoreGasToBucket method
            result = e.getResult();
            status = e.getMessage();
            throw e;
        } finally {
            if (!estimate) {
                restoreGasToBucket(result, params.getGas());

                // Only record metric if EVM is invoked and not inside estimate loop
                if (result != null) {
                    updateMetrics(params, result.gasUsed(), 1, status);
                }
            }
        }
        return result;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L154-161)
```java
    protected void validateResult(final EvmTransactionResult txnResult, final CallServiceParameters params) {
        if (!txnResult.isSuccessful()) {
            var revertReasonHex = txnResult.getErrorMessage().orElse(HEX_PREFIX);
            var detail = maybeDecodeSolidityErrorStringToReadableMessage(revertReasonHex);
            throw new MirrorEvmTransactionException(
                    txnResult.responseCodeEnum().protoName(), detail, revertReasonHex, txnResult);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L163-170)
```java
    protected final void updateMetrics(CallServiceParameters parameters, long gasUsed, int iterations, String status) {
        final var block = getBlock();
        final var callType = parameters.getCallType().toString();
        final var iterationTag = String.valueOf(iterations);
        var tags = Tags.of(TAG_STATUS, status, TAG_TYPE, callType);
        invocationCounter.withTags(tags.and(TAG_BLOCK, block)).increment();
        gasUsedCounter.withTags(tags.and(TAG_ITERATION, iterationTag)).increment(gasUsed);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L147-159)
```java
            if (ContractCallContext.get().getOpcodeContext() == null) {
                var processingResult = new EvmTransactionResult(status, result);

                final var errorMessageHex = processingResult.getErrorMessage().orElse(HEX_PREFIX);
                final var detail = maybeDecodeSolidityErrorStringToReadableMessage(errorMessageHex);
                throw new MirrorEvmTransactionException(
                        status, detail, errorMessageHex, processingResult, childTransactionErrors);
            } else {
                // If we are in an opcode trace scenario, we need to return a failed result in order to get the
                // opcode list from the ContractCallContext. If we throw an exception instead of returning a result,
                // as in the regular case, we won't be able to get the opcode list.
                return new EvmTransactionResult(status, result);
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/model/EvmTransactionResult.java (L39-41)
```java
    public boolean isSuccessful() {
        return responseCodeEnum != null && responseCodeEnum.equals(ResponseCodeEnum.SUCCESS);
    }
```
