### Title
Gas Throttle Bypass via `eth_estimateGas` Binary Search Amplification

### Summary
An unprivileged user can send a single `eth_estimateGas` request that triggers up to 21 full EVM executions (1 initial probe + up to 20 binary search iterations), while the gas throttle bucket is charged for only 1 execution. The binary search iterations in `BinaryGasEstimator.search()` call `doProcessCall(..., estimate=true)`, which unconditionally skips `restoreGasToBucket()` and all gas-throttle accounting, making them completely invisible to the rate limiter.

### Finding Description

**Exact code path:**

`ContractController.call()` → `ThrottleManagerImpl.throttle()` consumes `scaleGas(request.getGas())` tokens once from the gas bucket. [1](#0-0) 

`ContractExecutionService.estimateGas()` then performs:
1. An initial `callContract(params, context)` → `doProcessCall(params, params.getGas(), false)` — `estimate=false`, so `restoreGasToBucket()` is called and some gas is returned to the bucket. [2](#0-1) 

2. `binaryGasEstimator.search(...)` with up to `maxGasEstimateRetriesCount = 20` iterations, each calling `doProcessCall(params, gas, true)` — `estimate=true`. [3](#0-2) 

**Root cause:** In `ContractCallService.doProcessCall()`, the `finally` block is guarded by `if (!estimate)`. When `estimate=true` (all binary search iterations), `restoreGasToBucket()` is never called and no gas-throttle interaction occurs at all — neither consumption nor restoration. [4](#0-3) 

**Failed assumption:** The gas throttle was designed assuming one EVM execution per gas-bucket deduction. For `eth_estimateGas`, the design silently allows up to 21 EVM executions per single bucket deduction.

**Default configuration values:**
- `maxGasLimit = 15,000,000`
- `maxGasEstimateRetriesCount = 20`
- `gasPerSecond = 7,500,000,000` (scaled to 750,000 tokens)
- `requestsPerSecond = 500` [5](#0-4) [6](#0-5) 

### Impact Explanation

A single `eth_estimateGas` request against a contract consuming ~14.9M gas causes up to 21 full EVM executions while the gas throttle accounts for only 1. The gas bucket is debited `scaleGas(15_000_000) = 1500` tokens once, but 21 near-maximum-gas EVM runs execute. An attacker sending requests at the permitted 500 RPS rate can drive actual EVM execution throughput to ~10,500 full-gas executions per second instead of the intended ~500, a ~2000% amplification — far exceeding the 30% resource increase threshold. This can saturate CPU on the mirror node web3 service without triggering any throttle rejection.

### Likelihood Explanation

No privileges, API keys, or special accounts are required. Any user with network access to the `/api/v1/contracts/call` endpoint can exploit this. The attack is trivially repeatable: deploy or target any existing contract that consumes close to the 15M gas limit (e.g., a loop of SLOADs), then send `eth_estimateGas` requests at the allowed rate. The binary search will consistently run near the maximum iteration count because the gas usage is near the upper bound, keeping `lo` and `hi` far apart for many iterations. [7](#0-6) 

### Recommendation

The binary search iterations must be accounted for in the gas throttle. Specifically:

1. In `BinaryGasEstimator.search()` or in `ContractExecutionService.estimateGas()`, consume gas tokens from the throttle bucket for each binary search iteration before calling `doProcessCall(..., true)`. The consumed amount should be `scaleGas(mid)` for each iteration.
2. Alternatively, count the total gas consumed across all binary search iterations and deduct it from the bucket at the end of the estimate call (before returning).
3. As a defense-in-depth measure, add a separate per-request timeout specifically for the estimate loop, or reduce `maxGasEstimateRetriesCount` to a lower value (e.g., 10) to limit the amplification factor.
4. Consider adding a dedicated RPS limit for `eth_estimateGas` requests (separate from `eth_call`) since they are inherently more expensive.

### Proof of Concept

**Preconditions:**
- Access to the mirror node `/api/v1/contracts/call` endpoint (no authentication required by default)
- A deployed contract with a function that consumes ~14,500,000 gas (e.g., a loop performing 500+ SLOADs)

**Steps:**

1. Deploy a contract with a function that uses ~14.5M gas (near but below `maxGasLimit = 15,000,000`).

2. Send a single `eth_estimateGas` request:
```json
POST /api/v1/contracts/call
{
  "to": "<contract_address>",
  "data": "<expensive_function_selector>",
  "gas": 15000000,
  "estimate": true
}
```

3. Observe server-side: the `BinaryGasEstimator` runs up to 20 iterations. Since `gasUsedByInitialCall ≈ 14,500,000` and `hi = 15,000,000`, the search range is narrow but the gas values at each `mid` are near 15M. Each iteration executes a near-maximum-gas EVM run.

4. **Result:** 1 initial call + up to 20 binary search iterations = up to 21 full EVM executions. The gas throttle bucket is debited only `scaleGas(15,000,000) = 1500` tokens (equivalent to 1 execution). The 20 binary search iterations consume zero throttle tokens.

5. **Amplification:** Send this request at 500 RPS (the `requestsPerSecond` limit). Actual EVM executions reach ~10,500/second while the throttle believes only ~500/second are occurring, causing CPU to spike well above 30% of baseline. [8](#0-7) [9](#0-8)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L68-73)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;

    // Maximum iteration count for estimate gas' search algorithm
    @Positive
    private int maxGasEstimateRetriesCount = 20;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L22-35)
```java
    private float gasLimitRefundPercent = 100;

    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;
```
