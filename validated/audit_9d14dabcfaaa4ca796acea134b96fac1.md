All code references have been verified against the actual source. The finding is confirmed. Here is the audit report:

---

## Audit Report

## Title
Gas Throttle Bypass via `eth_estimateGas` Binary Search Amplification

## Summary
A single `eth_estimateGas` request triggers up to 21 full EVM executions (1 initial probe + up to 20 binary search iterations), while the gas throttle bucket is charged for only 1 execution. The binary search iterations in `BinaryGasEstimator.search()` call `doProcessCall(..., estimate=true)`, which unconditionally skips all gas-throttle accounting, making them invisible to the rate limiter.

## Finding Description

**Exact code path:**

`ContractController.call()` calls `throttleManager.throttle(request)`, which consumes `scaleGas(request.getGas())` tokens once from the gas bucket. [1](#0-0) 

`ThrottleManagerImpl.throttle()` deducts `scaleGas(request.getGas())` = `15,000,000 / 10,000 = 1,500` tokens from the gas bucket for a max-gas request. [2](#0-1) 

`ContractExecutionService.estimateGas()` then performs:
1. An initial `callContract(params, context)` → `doProcessCall(params, params.getGas(), false)` — `estimate=false`, so `restoreGasToBucket()` is called and some gas is returned. [3](#0-2) 

2. `binaryGasEstimator.search(...)` with up to `maxGasEstimateRetriesCount = 20` iterations, each calling `doProcessCall(params, gas, true)` — `estimate=true`. [4](#0-3) 

**Root cause:** In `ContractCallService.doProcessCall()`, the `finally` block is guarded by `if (!estimate)`. When `estimate=true` (all binary search iterations), `restoreGasToBucket()` is never called and no gas-throttle interaction occurs — neither consumption nor restoration. The code comment itself acknowledges this: *"Only record metric if EVM is invoked and not inside estimate loop."* [5](#0-4) 

`BinaryGasEstimator.search()` iterates up to `properties.getMaxGasEstimateRetriesCount()` (default: 20) times, each time invoking a full EVM execution via `safeCall(mid, call)`, with zero throttle interaction. [6](#0-5) 

**Default configuration values confirmed:**
- `maxGasLimit = 15,000,000`, `maxGasEstimateRetriesCount = 20` [7](#0-6) 
- `gasPerSecond = 7,500,000,000` (scaled to 750,000 tokens), `requestsPerSecond = 500` [8](#0-7) 
- `GAS_SCALE_FACTOR = 10,000` [9](#0-8) 

## Impact Explanation

A single `eth_estimateGas` request against a contract consuming ~14.9M gas causes up to 21 full EVM executions while the gas throttle accounts for only 1. The gas bucket is debited `scaleGas(15,000,000) = 1,500` tokens once; the initial probe restores approximately `scaleGas(15,000,000 - 14,900,000) = 10` tokens (net: ~1,490 tokens). The 20 binary search iterations execute with zero throttle interaction.

At the permitted 500 RPS rate, the gas bucket is fully consumed (`500 × 1,500 = 750,000 tokens/sec = gasPerSecond`), but actual EVM execution throughput reaches ~10,500 full-gas executions per second instead of the intended ~500 — a ~2,000% amplification. This can saturate CPU on the mirror node web3 service without triggering any throttle rejection. [10](#0-9) 

## Likelihood Explanation

No privileges, API keys, or special accounts are required. Any user with network access to the `/api/v1/contracts/call` endpoint can exploit this. The attack is trivially repeatable: target any existing contract that consumes close to the 15M gas limit (e.g., a loop of SLOADs). The binary search will consistently run near the maximum iteration count because with gas usage near the upper bound, `lo` and `hi` remain far apart for many iterations. [11](#0-10) 

## Recommendation

**Option 1 (preferred):** Charge the gas throttle for each binary search iteration. In `doProcessCall`, when `estimate=true`, still consume tokens from the gas bucket proportional to the `estimatedGas` argument passed to each iteration. This ensures the throttle accurately reflects actual EVM work.

**Option 2:** At the initial throttle check in `ContractController.call()`, multiply the gas deduction by a factor accounting for the expected number of binary search iterations when `request.isEstimate() == true` (e.g., multiply by `maxGasEstimateRetriesCount + 1`). [12](#0-11) 

**Option 3:** Reduce `maxGasEstimateRetriesCount` significantly, or add a separate per-request throttle specifically for `eth_estimateGas` requests. [13](#0-12) 

## Proof of Concept

1. Deploy or identify any contract that consumes ~14,900,000 gas (e.g., a tight loop of `SLOAD` opcodes).
2. Send `POST /api/v1/contracts/call` with `{"estimate": true, "gas": 15000000, "to": "<contract_address>", "data": "<calldata>"}`.
3. Observe in server-side profiling that `transactionExecutionService.execute()` is called up to 21 times per HTTP request:
   - Once in `callContract()` via `doProcessCall(..., false)` (initial probe)
   - Up to 20 times in `BinaryGasEstimator.search()` via `doProcessCall(..., true)` (binary search)
4. Confirm via `ThrottleManagerImpl` that `gasLimitBucket.tryConsume()` is called exactly once and `gasLimitBucket.addTokens()` is called at most once (for the initial probe restoration), with zero throttle interaction for the 20 binary search iterations. [14](#0-13) 
5. Repeat at 500 RPS to demonstrate CPU saturation without any `ThrottleException` being thrown. [2](#0-1)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L59-64)
```java
    public void restore(long gas) {
        long tokens = throttleProperties.scaleGas(gas);
        if (tokens > 0) {
            gasLimitBucket.addTokens(tokens);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L100-107)
```java
    protected final EvmTransactionResult callContract(CallServiceParameters params, ContractCallContext ctx)
            throws MirrorEvmTransactionException {
        ctx.setCallServiceParameters(params);
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));

        return doProcessCall(params, params.getGas(), false);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L91-95)
```java
        final var estimatedGas = binaryGasEstimator.search(
                (totalGas, iterations) -> updateMetrics(params, totalGas, iterations, status),
                gas -> doProcessCall(params, gas, true),
                gasUsedByInitialCall,
                params.getGas());
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java (L35-62)
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

        metricUpdater.accept(totalGasUsed, iterationsMade);
        return hi;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L18-18)
```java
    private static final long GAS_SCALE_FACTOR = 10_000L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L26-35)
```java
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;
```
