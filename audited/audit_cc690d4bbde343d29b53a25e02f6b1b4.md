### Title
Unthrottled Binary Search EVM Simulation Amplification in `estimate=true` Requests

### Summary
Any unprivileged caller can POST to `/api/v1/contracts/call` with `estimate=true` and a `data` payload targeting a contract function with many SSTORE operations. The gas throttle is consumed only once upfront, but `BinaryGasEstimator.search()` then executes up to 20 additional full EVM simulations per request with no further throttle interaction, creating a ~21x amplification in actual CPU/memory consumption relative to what the throttle accounts for.

### Finding Description

**Exact code path:**

`ContractController.call()` (line 40) calls `throttleManager.throttle(request)` exactly once, consuming `scaleGas(request.getGas())` tokens from the gas bucket: [1](#0-0) 

`ThrottleManagerImpl.throttle()` deducts `scaleGas(gas)` = `gas / 10_000` tokens from the bucket. With `gas=15,000,000`, that is 1,500 tokens from a 750,000-token/second bucket: [2](#0-1) [3](#0-2) 

When `estimate=true`, `ContractExecutionService.estimateGas()` first runs one initial call via `callContract()` (which internally calls `doProcessCall(..., false)`), then hands a lambda `gas -> doProcessCall(params, gas, true)` to `BinaryGasEstimator.search()`: [4](#0-3) 

`BinaryGasEstimator.search()` loops up to `maxGasEstimateRetriesCount = 20` times, calling `doProcessCall` with `estimate=true` on each iteration: [5](#0-4) 

`doProcessCall` with `estimate=true` skips both `restoreGasToBucket` and any additional throttle consumption entirely: [6](#0-5) 

**Root cause:** The gas throttle is designed to limit computational load by treating gas as a proxy for EVM work. For `estimate=true` requests, the throttle is charged once (for the initial call, with unused gas restored), but the binary search loop executes up to 20 additional full EVM simulations — each re-executing the entire contract including all SSTORE opcodes — with zero additional throttle interaction. The failed assumption is that one throttle deduction corresponds to one EVM execution.

**Why existing checks fail:**
- The `requestsPerSecond = 500` RPS bucket limits concurrent requests but does not account for the 20x simulation multiplier per request.
- The `maxGasEstimateRetriesCount = 20` cap bounds the amplification but does not eliminate it.
- The `maxGasLimit = 15,000,000` cap limits per-simulation gas but does not reduce the iteration count.
- The `requestTimeout = 10,000ms` provides a wall-clock bound but still allows many iterations within that window. [7](#0-6) 

### Impact Explanation
Each `estimate=true` request at max gas triggers 1 initial EVM simulation + up to 20 binary search simulations = up to 21 full EVM executions. The throttle accounts for approximately 1 execution worth of gas (after restoration of unused gas from the initial call). An attacker targeting a contract with many SSTORE operations forces the server to perform expensive in-memory state-write simulations (database reads for current slot values, in-memory journal tracking) for each of the 20 iterations. With 500 concurrent RPS, the server processes up to 10,500 EVM simulations/second instead of the intended ~500. This degrades service availability for legitimate users — a griefing attack with no on-chain state changes and no economic damage.

### Likelihood Explanation
The `/api/v1/contracts/call` endpoint is public and requires no authentication or privileges. The `estimate=true` flag is a standard JSON field. Any attacker with HTTP access can craft the request. The attack is trivially repeatable with a simple script, requires no special knowledge beyond the API schema, and can be sustained indefinitely. The amplification factor (up to 21x) is deterministic and predictable.

### Recommendation
1. **Charge throttle tokens proportional to binary search iterations**: Before entering `BinaryGasEstimator.search()`, pre-consume additional gas tokens scaled by `maxGasEstimateRetriesCount`, or consume tokens inside each binary search iteration call.
2. **Alternatively, apply a separate per-request estimate-call rate limit** distinct from the general RPS bucket, specifically for `estimate=true` requests.
3. **Reduce `maxGasEstimateRetriesCount`** from 20 to a lower value (e.g., 10) to reduce the amplification ceiling.
4. **Account for estimate multiplier in `scaleGas`**: When `isEstimate=true`, multiply the consumed gas tokens by an estimate overhead factor (e.g., `log2(maxGasLimit / minGas)`) before deducting from the bucket.

### Proof of Concept

**Preconditions:** A deployed contract on the mirror node's tracked state that performs N SSTORE operations (e.g., a loop writing to N distinct storage slots). No account or credentials required.

**Steps:**
```
POST /api/v1/contracts/call
Content-Type: application/json

{
  "to": "<contract_address_with_many_sstores>",
  "data": "<selector_for_sstore_heavy_function>",
  "gas": 15000000,
  "estimate": true
}
```

**Trigger:** Send this request in a loop at the maximum allowed RPS (500/second). Each request causes:
1. One initial EVM simulation at 15M gas (gas partially restored to bucket)
2. Up to 20 binary search EVM simulations at varying gas limits, each re-executing all SSTORE logic in-memory

**Result:** The server executes up to 10,500 EVM simulations/second (21 × 500 RPS) while the throttle only accounts for ~500 executions worth of gas. CPU and memory consumption spike proportionally, degrading response times for all users. No state is persisted and no economic cost is incurred by the attacker.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-51)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-48)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L81-98)
```java
    private Bytes estimateGas(final ContractExecutionParameters params, final ContractCallContext context) {
        final var processingResult = callContract(params, context);
        final var gasUsedByInitialCall = processingResult.gasUsed();

        // sanity check ensuring gasUsed is always lower than the inputted one
        if (gasUsedByInitialCall >= params.getGas()) {
            return Bytes.ofUnsignedLong(gasUsedByInitialCall);
        }

        final var status = ResponseCodeEnum.SUCCESS.toString();
        final var estimatedGas = binaryGasEstimator.search(
                (totalGas, iterations) -> updateMetrics(params, totalGas, iterations, status),
                gas -> doProcessCall(params, gas, true),
                gasUsedByInitialCall,
                params.getGas());

        return Bytes.ofUnsignedLong(estimatedGas);
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L127-135)
```java
        } finally {
            if (!estimate) {
                restoreGasToBucket(result, params.getGas());

                // Only record metric if EVM is invoked and not inside estimate loop
                if (result != null) {
                    updateMetrics(params, result.gasUsed(), 1, status);
                }
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L68-73)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;

    // Maximum iteration count for estimate gas' search algorithm
    @Positive
    private int maxGasEstimateRetriesCount = 20;
```
