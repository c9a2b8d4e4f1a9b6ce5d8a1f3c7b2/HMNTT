All four code references check out against the actual source. Let me confirm each claim:

**`safeCall` swallows all exceptions** — confirmed at lines 67–74. [1](#0-0) 

**`null` maps to `lo = mid`** — confirmed at lines 45–50. [2](#0-1) 

**`doProcessCall` re-throws `MirrorEvmTransactionException` regardless of `estimate` flag** — confirmed at lines 122–126. [3](#0-2) 

**`TransactionExecutionService.handleFailedResult` throws `MirrorEvmTransactionException` for ALL failed EVM calls** (not just pre-check failures) — confirmed at lines 148–153. This is the critical missing piece: reverts reach `safeCall` as exceptions, not as failed `EvmTransactionResult` objects. [4](#0-3) 

**Lambda wiring** — confirmed at lines 91–95. [5](#0-4) 

Nothing in SECURITY.md excludes this finding. It is not a best-practice recommendation, does not require privileged access, and is not theoretical. [6](#0-5) 

---

# Audit Report

## Title
Silent Exception Swallowing in `BinaryGasEstimator.safeCall()` Causes Gas Estimate Inflation Without Error Surfacing

## Summary
`BinaryGasEstimator.safeCall()` catches all `Exception` subtypes and returns `null`. The binary search loop unconditionally treats `null` as "gas insufficient" by advancing `lo = mid`. Because `TransactionExecutionService.handleFailedResult()` throws `MirrorEvmTransactionException` for every EVM-level failure (including contract reverts), and `doProcessCall` re-throws that exception regardless of the `estimate` flag, a contract that reverts at every intermediate gas value will cause the binary search to converge on `hi` (the caller-supplied ceiling, up to 15 M gas). The caller receives that inflated value as a normal `200 OK` with no error indication.

## Finding Description

**`BinaryGasEstimator.safeCall()` — lines 67–74:**
```java
private EvmTransactionResult safeCall(long mid, LongFunction<EvmTransactionResult> call) {
    try {
        return call.apply(mid);
    } catch (Exception ignored) {          // catches MirrorEvmTransactionException
        log.info("Exception while calling contract for gas estimation");
        return null;                        // null == "gas too low" to the caller
    }
}
``` [1](#0-0) 

**`BinaryGasEstimator.search()` — lines 45–50:** `null` is treated identically to an OOG result:
```java
boolean err = transactionResult == null || !transactionResult.isSuccessful() || transactionResult.gasUsed() < 0;
...
if (err || gasUsed == 0) {
    lo = mid;   // "gas was too low, raise the floor"
}
``` [2](#0-1) 

**`ContractCallService.doProcessCall()` — lines 122–126:** `MirrorEvmTransactionException` is re-thrown unconditionally, even when `estimate=true`:
```java
} catch (MirrorEvmTransactionException e) {
    result = e.getResult();
    status = e.getMessage();
    throw e;   // no guard on the estimate flag
}
``` [3](#0-2) 

**`TransactionExecutionService.handleFailedResult()` — lines 148–153:** Every EVM-level failure (including a plain contract revert) throws `MirrorEvmTransactionException` rather than returning a failed result object:
```java
throw new MirrorEvmTransactionException(
        status, detail, errorMessageHex, processingResult, childTransactionErrors);
``` [4](#0-3) 

**`ContractExecutionService.estimateGas()` — lines 91–95:** The lambda wiring that connects all of the above:
```java
gas -> doProcessCall(params, gas, true)
``` [5](#0-4) 

**Root cause:** The binary search assumes that any exception means "gas was insufficient." `TransactionExecutionService` throws `MirrorEvmTransactionException` for all EVM failures, including reverts that are entirely unrelated to gas. `safeCall` cannot distinguish between the two; it maps both to `null`, which the loop treats as `lo = mid`.

## Impact Explanation
The caller receives a massively inflated gas estimate (up to the configured `maxGasLimit`, default 15 M) with HTTP 200 and no error field. On Hedera, gas limits directly determine transaction fees. A user who trusts this estimate and submits a transaction with a 15 M gas limit will pay the maximum possible fee for what may be a trivially cheap operation. Because the response is a normal hex-encoded integer, client libraries (ethers.js, web3.js, MetaMask) have no signal that the estimate is unreliable and will use it as-is.

## Likelihood Explanation
No special privileges are required. Any account holding enough HBAR to deploy a contract can execute this attack. The required contract logic is trivial:

```solidity
function f() external {
    require(gasleft() >= 14_999_000, "gas check");
    // cheap operation
}
```

This succeeds at the 15 M initial probe and reverts at every intermediate binary-search value. The attack is fully repeatable and deterministic. A malicious dApp can silently route all `eth_estimateGas` calls through such a contract.

## Recommendation

1. **Distinguish revert exceptions from OOG exceptions inside `safeCall`.** Inspect the exception type or the embedded `ResponseCodeEnum` status. Only treat the result as "gas too low" when the failure is genuinely gas-related (e.g., `INSUFFICIENT_GAS`, `OUT_OF_GAS`). For all other `MirrorEvmTransactionException` statuses, re-throw the exception so it propagates out of `estimateGas` as an error.

2. **Return a failed `EvmTransactionResult` instead of throwing for EVM-level reverts during estimation.** In `TransactionExecutionService.handleFailedResult()`, when `estimate=true` is in effect, return the `EvmTransactionResult` with `isSuccessful() == false` rather than throwing. The binary search already handles `!isSuccessful()` correctly as a non-gas failure if the loop is also fixed to distinguish it from OOG.

3. **Add a guard in `doProcessCall`:** When `estimate=true`, catch `MirrorEvmTransactionException` and return the embedded result (or re-throw only for gas-related codes) rather than unconditionally re-throwing.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GasInflator {
    // Succeeds only when called with ~15M gas (initial probe).
    // Reverts at every intermediate binary-search value.
    function f() external pure returns (uint256) {
        require(gasleft() >= 14_990_000, "revert at mid");
        return 42;
    }
}
```

**Steps:**
1. Deploy `GasInflator` on the target network.
2. Call `eth_estimateGas` with `to=<GasInflator>`, `data=<selector of f()>`, `gas=15000000`.
3. Mirror node runs initial probe at 15 M → `gasleft() >= 14_990_000` → succeeds; `gasUsedByInitialCall` ≈ a few thousand gas.
4. Binary search: `lo ≈ small`, `hi = 15_000_000`. Each `mid` probe (≈7.5 M, 11.25 M, …) triggers `require` revert → `MirrorEvmTransactionException` → caught by `safeCall` → `null` → `lo = mid`.
5. After `maxGasEstimateRetriesCount` iterations, `lo` converges toward `hi`; `search` returns `hi = 15_000_000`.
6. Response: `{"result":"0xE4E1C0"}` with HTTP 200. Caller pays maximum fees.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java (L45-50)
```java
            boolean err =
                    transactionResult == null || !transactionResult.isSuccessful() || transactionResult.gasUsed() < 0;
            long gasUsed = err ? prevGasLimit : transactionResult.gasUsed();
            totalGasUsed += gasUsed;
            if (err || gasUsed == 0) {
                lo = mid;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java (L67-74)
```java
    private EvmTransactionResult safeCall(long mid, LongFunction<EvmTransactionResult> call) {
        try {
            return call.apply(mid);
        } catch (Exception ignored) {
            log.info("Exception while calling contract for gas estimation");
            return null;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L122-126)
```java
        } catch (MirrorEvmTransactionException e) {
            // This result is needed in case of exception to be still able to call restoreGasToBucket method
            result = e.getResult();
            status = e.getMessage();
            throw e;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L148-153)
```java
                var processingResult = new EvmTransactionResult(status, result);

                final var errorMessageHex = processingResult.getErrorMessage().orElse(HEX_PREFIX);
                final var detail = maybeDecodeSolidityErrorStringToReadableMessage(errorMessageHex);
                throw new MirrorEvmTransactionException(
                        status, detail, errorMessageHex, processingResult, childTransactionErrors);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L91-95)
```java
        final var estimatedGas = binaryGasEstimator.search(
                (totalGas, iterations) -> updateMetrics(params, totalGas, iterations, status),
                gas -> doProcessCall(params, gas, true),
                gasUsedByInitialCall,
                params.getGas());
```

**File:** SECURITY.md (L1-16)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.
```
