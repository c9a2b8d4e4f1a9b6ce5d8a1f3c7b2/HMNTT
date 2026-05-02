### Title
Gas Throttle Bypass via Binary Search Iterations in `estimateGas()` Enabling Resource Exhaustion

### Summary
When `isEstimate=true`, `ContractExecutionService.estimateGas()` invokes `BinaryGasEstimator.search()` which calls `doProcessCall(params, gas, true)` up to 20 times. Because `estimate=true` causes `restoreGasToBucket()` to be skipped in the `finally` block of `doProcessCall`, these binary search EVM executions are completely invisible to the gas throttle. Combined with the default `gasLimitRefundPercent=100` restoring nearly all gas after the first call, an unprivileged attacker can trigger up to 21 full EVM executions per request while the gas bucket is only meaningfully depleted by the gas used in the first call, multiplying actual EVM load by up to 21x beyond what the throttle accounts for.

### Finding Description

**Code path:**

`ContractController.java:40` — `throttleManager.throttle(request)` consumes `scaleGas(request.getGas())` tokens from `gasLimitBucket` and 1 token from `rateLimitBucket` for every request, including estimate requests. [1](#0-0) 

`ContractExecutionService.java:53-54` — If `params.isEstimate()`, execution branches to `estimateGas()`. [2](#0-1) 

`ContractExecutionService.java:82` — `estimateGas()` first calls `callContract(params, context)` which internally calls `doProcessCall(params, params.getGas(), false)` — the `false` flag means `restoreGasToBucket()` IS called here, restoring up to `gasLimitRefundPercent` (default 100%) of remaining gas back to the bucket. [3](#0-2) 

`ContractExecutionService.java:91-95` — Then `binaryGasEstimator.search()` is called, passing `gas -> doProcessCall(params, gas, true)` as the call lambda. [4](#0-3) 

`BinaryGasEstimator.java:35` — The binary search loop runs up to `maxGasEstimateRetriesCount` (default 20) iterations, each invoking the EVM via `doProcessCall(..., true)`. [5](#0-4) 

`ContractCallService.java:127-135` — The `finally` block in `doProcessCall` only calls `restoreGasToBucket()` when `!estimate`. When `estimate=true`, the block is skipped entirely — no gas bucket interaction occurs for any of the 20 binary search EVM executions. [6](#0-5) 

**Root cause:** The gas throttle design assumes one gas deduction per request, with partial restoration after execution. For estimate requests, the first call restores nearly all gas (default `gasLimitRefundPercent=100`), and the 20 binary search iterations execute the EVM with zero gas bucket interaction. The throttle's failed assumption is that one request = one EVM execution. [7](#0-6) 

### Impact Explanation
Each estimate request with `gas=15_000_000` (max) causes:
- 1 gas deduction of 15M at the controller
- ~14M+ gas restored after the first call (since `gasLimitRefundPercent=100` and a typical call uses far less than 15M)
- 20 additional EVM executions with zero gas bucket cost

Net gas bucket cost per estimate request ≈ gas used in first call only (e.g., ~50K–500K for a staking precompile call), while actual EVM work = 21 executions. At the default rate limit of 500 req/s, an attacker drives ~10,500 EVM executions/second while the gas throttle accounts for only ~500. This exhausts CPU, thread pool, and database connection resources on the mirror node, causing denial of service for legitimate users. The mirror node is read-only so no on-chain state is modified, but the service availability is directly impacted. [8](#0-7) 

### Likelihood Explanation
No authentication or special privilege is required — the `/api/v1/contracts/call` endpoint is public. The attacker only needs to set `estimate: true` in the JSON body. The attack is trivially scriptable: send 500 concurrent POST requests per second with `estimate: true`, `gas: 15000000`, and any valid contract address. The binary search multiplier is deterministic and reliable. The attack is repeatable indefinitely. [9](#0-8) 

### Recommendation
1. **Apply gas throttle to binary search iterations**: Pass a per-iteration gas cost to `throttleManager` inside `BinaryGasEstimator.search()`, or deduct a fixed overhead per estimate request proportional to `maxGasEstimateRetriesCount`.
2. **Separate rate limit for estimate requests**: Add a dedicated lower `requestsPerSecond` limit for `isEstimate=true` requests, configurable via `throttle.request[].filters[].field=ESTIMATE`.
3. **Reduce `maxGasEstimateRetriesCount`**: Lower the default from 20 to a smaller value (e.g., 10) to reduce the multiplier.
4. **Do not restore gas after the first call in estimate mode**: The near-full restoration of gas after the first `callContract` call (due to `gasLimitRefundPercent=100`) means the gas bucket is barely depleted per estimate request, compounding the issue. [10](#0-9) 

### Proof of Concept
```bash
# Send 500 concurrent estimate requests per second (within rate limit)
# Each triggers 21 EVM executions; gas bucket barely depleted due to 100% refund

for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d '{
      "to": "0x0000000000000000000000000000000000000167",
      "data": "0x<staking_precompile_selector>",
      "gas": 15000000,
      "estimate": true
    }' &
done
wait
# Repeat in a loop — each second: 500 requests × 21 EVM executions = 10,500 EVM calls
# vs. intended throttle ceiling of ~500 EVM calls/second
# Mirror node CPU/thread pool saturates; legitimate requests receive 429 or timeout
``` [11](#0-10)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L53-54)
```java
                if (params.isEstimate()) {
                    result = estimateGas(params, ctx);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L82-84)
```java
        final var processingResult = callContract(params, context);
        final var gasUsedByInitialCall = processingResult.gasUsed();

```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L91-95)
```java
        final var estimatedGas = binaryGasEstimator.search(
                (totalGas, iterations) -> updateMetrics(params, totalGas, iterations, status),
                gas -> doProcessCall(params, gas, true),
                gasUsedByInitialCall,
                params.getGas());
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java (L35-58)
```java
        while (lo + 1 < hi && iterationsMade < properties.getMaxGasEstimateRetriesCount()) {
            contractCallContext.reset();

            long mid = (hi + lo) / 2;

            // If modularizedServices is true - we call the safeCall function that handles if an exception is thrown
            final var transactionResult = safeCall(mid, call);

            iterationsMade++;

            boolean err =
                    transactionResult == null || !transactionResult.isSuccessful() || transactionResult.gasUsed() < 0;
            long gasUsed = err ? prevGasLimit : transactionResult.gasUsed();
            totalGasUsed += gasUsed;
            if (err || gasUsed == 0) {
                lo = mid;
            } else {
                hi = mid;
                if (Math.abs(prevGasLimit - mid) < estimateIterationThreshold) {
                    lo = hi;
                }
            }
            prevGasLimit = mid;
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L127-136)
```java
        } finally {
            if (!estimate) {
                restoreGasToBucket(result, params.getGas());

                // Only record metric if EVM is invoked and not inside estimate loop
                if (result != null) {
                    updateMetrics(params, result.gasUsed(), 1, status);
                }
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L22-22)
```java
    private float gasLimitRefundPercent = 100;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L35-35)
```java
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```
