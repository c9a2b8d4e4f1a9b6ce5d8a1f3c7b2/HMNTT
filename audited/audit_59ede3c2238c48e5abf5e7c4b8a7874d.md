### Title
Gas Estimation Binary Search Bypasses Throttle Accounting, Enabling CPU Amplification DoS

### Summary
The `call()` endpoint in `ContractController.java` invokes `throttleManager.throttle(request)` exactly once, consuming gas tokens proportional to `request.getGas()`. However, when `estimate=true`, the `estimateGas()` method performs one initial full EVM execution followed by up to 20 additional EVM re-executions inside `BinaryGasEstimator.search()`, none of which are throttle-checked or gas-token-accounted. An unprivileged attacker can craft a request targeting a contract with many SSTORE operations to amplify actual CPU/memory work by up to 21× per throttle token consumed.

### Finding Description

**Exact code path:**

`ContractController.call()` (lines 38–51) calls `throttleManager.throttle(request)` once, consuming tokens for `request.getGas()` (max 15,000,000): [1](#0-0) 

`ThrottleManagerImpl.throttle()` (lines 37–48) consumes exactly 1 request token and `scaleGas(request.getGas())` gas tokens — a one-time charge for the entire request lifecycle: [2](#0-1) 

`ContractExecutionService.estimateGas()` (lines 81–98) then performs:
1. One initial full EVM call via `callContract(params, context)` (line 82)
2. Up to `maxGasEstimateRetriesCount = 20` additional EVM executions inside `binaryGasEstimator.search()` (line 91–95), each calling `doProcessCall(params, gas, true)` [3](#0-2) 

`BinaryGasEstimator.search()` (lines 35–58) loops up to `maxGasEstimateRetriesCount` times, calling `safeCall(mid, call)` each iteration with no throttle interaction: [4](#0-3) 

**Root cause — `doProcessCall` skips gas restoration for estimate iterations:**

In `ContractCallService.doProcessCall()` (lines 128–135), `restoreGasToBucket` is only called when `estimate=false`. All 20 binary search iterations pass `estimate=true`, so no gas tokens are restored and no throttle check occurs for any of them: [5](#0-4) 

**Why existing checks fail:**

- The gas bucket (`gasPerSecond = 7,500,000,000`, scaled by 10,000 → 750,000 tokens/sec) is charged once for `scaleGas(15,000,000) = 1,500` tokens, allowing ~500 estimate requests/sec.
- Each such request triggers 21 EVM executions (1 initial + 20 binary search), so the real CPU throughput is 21 × 500 = **10,500 full EVM executions/sec** — 21× what the throttle accounts for.
- `requestsPerSecond = 500` limits HTTP requests but not the per-request EVM amplification.
- `maxGasLimit` validation (lines 92–97) only caps the declared gas, not the number of EVM re-executions: [6](#0-5) [7](#0-6) 

### Impact Explanation

Each estimate request with `gas=15,000,000` targeting a contract that performs many SSTORE operations causes up to 21 full EVM simulations. SSTORE costs 20,000 gas cold, so a single 15M-gas execution can simulate ~750 storage writes. Across 21 iterations, that is ~15,750 simulated storage writes per HTTP request. At the permitted 500 requests/sec, this yields ~7.8 million simulated SSTORE operations/sec, consuming disproportionate CPU and heap memory (EVM state frames, journal entries). This can saturate server CPU and trigger GC pressure or OOM, constituting a denial-of-service against the mirror node's web3 API with no economic cost to the attacker.

### Likelihood Explanation

No authentication or API key is required — the endpoint is publicly accessible. The attacker only needs to know the address of any deployed contract with a storage-writing function (or deploy one themselves on a public network). The attack is trivially repeatable with a simple HTTP client loop. The 21× amplification factor is deterministic and consistent across all estimate requests at max gas.

### Recommendation

1. **Charge throttle tokens proportional to actual EVM invocations**: multiply the gas token cost by `maxGasEstimateRetriesCount + 1` when `request.isEstimate() == true`, or consume additional tokens inside `BinaryGasEstimator.search()` per iteration.
2. **Add a per-iteration throttle check** inside `BinaryGasEstimator.search()` by injecting a throttle callback that is called before each `safeCall`.
3. **Reduce `maxGasEstimateRetriesCount`** from 20 to a lower value (e.g., 10) to limit worst-case amplification.
4. **Apply a separate, stricter rate limit for estimate requests** using the existing `RequestFilter` mechanism with `ESTIMATE` field and `ActionType.THROTTLE`.

### Proof of Concept

```bash
# Deploy or identify a contract with a function that performs many SSTOREs
# e.g., a loop writing to 100 storage slots

# Craft calldata for the SSTORE-heavy function
CALLDATA="0x<sstore_heavy_function_selector_and_args>"
CONTRACT="0x<deployed_contract_address>"

# Send concurrent estimate requests at max gas
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{
      \"to\": \"$CONTRACT\",
      \"data\": \"$CALLDATA\",
      \"gas\": 15000000,
      \"estimate\": true
    }" &
done
wait
# Each request triggers 21 EVM executions; 500 concurrent requests = 10,500 EVM runs
# CPU spikes to 100%, GC pressure increases, subsequent requests time out
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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L92-97)
```java
    private void validateContractMaxGasLimit(ContractCallRequest request) {
        if (request.getGas() > evmProperties.getMaxGasLimit()) {
            throw new InvalidParametersException(
                    "gas field must be less than or equal to %d".formatted(evmProperties.getMaxGasLimit()));
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L68-73)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;

    // Maximum iteration count for estimate gas' search algorithm
    @Positive
    private int maxGasEstimateRetriesCount = 20;
```
