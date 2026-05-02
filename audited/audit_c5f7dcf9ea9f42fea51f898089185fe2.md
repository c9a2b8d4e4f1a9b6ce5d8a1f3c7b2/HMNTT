### Title
Gas Estimation Binary Search Amplification: 21x EVM Execution Per Throttle Token

### Summary
Any unauthenticated user can POST to `/api/v1/contracts/call` with `estimate=true` and arbitrary EVM bytecode in the `data` field. The throttle mechanism consumes gas-bucket tokens exactly once per HTTP request, but the gas estimation path executes the full EVM up to 21 times (1 initial probe + up to 20 binary search iterations). This creates a 21x CPU amplification factor that the throttle does not account for.

### Finding Description

**Entry point** — `ContractController.call()` requires no authentication: [1](#0-0) 

**Throttle consumed once** — `ThrottleManagerImpl.throttle()` deducts `scaleGas(request.getGas())` tokens from the gas bucket a single time before any EVM execution begins: [2](#0-1) 

**Estimate path forks into binary search** — `ContractExecutionService.estimateGas()` first runs one full EVM call, then hands off to `BinaryGasEstimator.search()`: [3](#0-2) 

**Binary search runs up to 20 additional EVM executions** — the loop condition is `iterationsMade < properties.getMaxGasEstimateRetriesCount()` where `maxGasEstimateRetriesCount = 20`: [4](#0-3) [5](#0-4) 

**Gas bucket is never restored or re-consumed during binary search** — `restoreGasToBucket` is guarded by `if (!estimate)`, so the 20 inner iterations neither consume nor restore any throttle tokens: [6](#0-5) 

**Early-exit threshold can be defeated** — the only early-exit condition inside the loop is `Math.abs(prevGasLimit - mid) < estimateIterationThreshold`, where the threshold is `lo * 0.10`. An attacker whose bytecode consumes gas near the midpoint of each interval keeps the search running for all 20 iterations: [7](#0-6) 

**Root cause**: The throttle model assumes one gas-bucket deduction ≈ one EVM execution. For `estimate=true` requests, the actual ratio is 1 deduction : up to 21 EVM executions.

### Impact Explanation

With default settings (`gasPerSecond = 7,500,000,000`, `maxGasLimit = 15,000,000`, `requestsPerSecond = 500`):

- Gas bucket allows ≈ 500 estimate requests/second (7.5 B / 15 M = 500).
- Each estimate request triggers up to 21 full EVM executions.
- Effective EVM execution rate: **up to 10,500 per second** vs. the intended 500.

An attacker sending crafted `estimate=true` requests at the permitted rate forces the server to perform 21× the expected CPU work, leading to sustained CPU saturation and denial of service for all users of the mirror-node web3 API.

### Likelihood Explanation

- **No authentication or API key required** — the endpoint is fully public.
- **No per-IP rate limiting** in the codebase — a single IP can exhaust the global bucket.
- **Trivially repeatable** — a simple loop with `curl` or any HTTP client suffices; no on-chain funds or special privileges needed.
- **Amplification is deterministic** — the attacker can reliably force 20 iterations by supplying bytecode whose gas usage bisects the search range each time (e.g., a loop whose iteration count is proportional to the supplied gas limit).

### Recommendation

1. **Multiply the gas-bucket cost for estimate requests** by `maxGasEstimateRetriesCount` at the point of throttle consumption in `ContractController.call()` (or inside `ContractExecutionService.estimateGas()`), so the throttle reflects the true worst-case EVM invocation count.
2. **Alternatively**, consume one additional gas-bucket token per binary search iteration inside `BinaryGasEstimator.search()`, calling `throttleManager.throttle`-equivalent logic each iteration.
3. **Add per-IP rate limiting** (e.g., via a reverse proxy or a per-source bucket) to prevent a single client from monopolising the global budget.
4. Consider reducing `maxGasEstimateRetriesCount` or making it configurable with a lower default, and document the CPU cost implications.

### Proof of Concept

```bash
# Craft a request: estimate=true, max gas, bytecode that loops proportionally to gas
# (any non-trivial bytecode forces the full 20 iterations)
PAYLOAD='{
  "estimate": true,
  "gas": 15000000,
  "data": "0x<loop_bytecode>",
  "to": "0x0000000000000000000000000000000000000001"
}'

# Send at the permitted rate (~500 req/s) from a single unauthenticated client
for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
       -H 'Content-Type: application/json' \
       -d "$PAYLOAD" &
done
wait
# Server performs up to 10,500 full EVM executions instead of 500,
# saturating CPU while the attacker stays within the published rate limit.
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java (L32-58)
```java
        final long estimateIterationThreshold = (long) (lo * properties.getEstimateGasIterationThresholdPercent());

        ContractCallContext contractCallContext = ContractCallContext.get();
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L67-69)
```java
    // Maximum iteration count for estimate gas' search algorithm
    @Positive
    private int maxGasEstimateRetriesCount = 20;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L128-135)
```java
            if (!estimate) {
                restoreGasToBucket(result, params.getGas());

                // Only record metric if EVM is invoked and not inside estimate loop
                if (result != null) {
                    updateMetrics(params, result.gasUsed(), 1, status);
                }
            }
```
