I have verified all the code references. Here is my assessment:

---

Audit Report

## Title
Gas Estimation Binary Search Bypasses Per-Request Gas Throttle, Enabling Up to 20x EVM Execution Amplification

## Summary
A single HTTP `POST /api/v1/contracts/call` request with `estimate=true` passes one `rateLimitBucket` token check and one `gasLimitBucket` deduction, but internally triggers 1 initial EVM execution (which does restore gas to the bucket) plus up to 20 additional binary-search EVM executions via `BinaryGasEstimator.search()`. All binary-search iterations bypass `restoreGasToBucket` entirely because the `finally` block in `doProcessCall` is gated on `!estimate`. An unprivileged attacker sending max-gas estimate requests at the allowed RPS can force up to 20x the EVM CPU/memory work per rate-limit token compared to a normal `eth_call`.

## Finding Description

**Entry point — `ContractController.call()`:**

`throttleManager.throttle(request)` is called exactly once per HTTP request. [1](#0-0) 

**`ThrottleManagerImpl.throttle()`** consumes 1 token from `rateLimitBucket` and `scaleGas(request.getGas())` tokens from `gasLimitBucket`. With `GAS_SCALE_FACTOR = 10_000` and `gas = 15_000_000`, this deducts 1,500 tokens. [2](#0-1) [3](#0-2) 

**Estimate path — `ContractExecutionService.estimateGas()`:**

Step 1: `callContract(params, context)` → `doProcessCall(params, params.getGas(), false)` — one full EVM execution at 15M gas. Because `estimate=false`, `restoreGasToBucket` **is** called, so the gas bucket is partially refilled. [4](#0-3) 

Step 2: `binaryGasEstimator.search(...)` is called with `gas -> doProcessCall(params, gas, true)`. The binary search loop runs up to `maxGasEstimateRetriesCount` (default **20**) iterations: [5](#0-4) [6](#0-5) 

Each iteration calls `doProcessCall(params, gas, true)`. Inside `doProcessCall`, the `finally` block that calls `restoreGasToBucket` is **gated on `!estimate`**: [7](#0-6) 

**Root cause:** The 20 binary-search EVM executions:
1. Never call `throttleManager.throttle()` — no RPS or gas bucket tokens consumed.
2. Never call `restoreGasToBucket` — no gas accounting at all.
3. Are bounded only by `maxGasEstimateRetriesCount = 20` (a functional tuning parameter, not a security control). [8](#0-7) 

Default values confirmed:
- `maxGasLimit = 15_000_000`
- `maxGasEstimateRetriesCount = 20`
- `requestsPerSecond = 500` [8](#0-7) [9](#0-8) 

## Impact Explanation
A single estimate request with `gas=15,000,000` triggers up to 21 EVM executions (1 initial + up to 20 binary search) while consuming only 1 RPS token. The initial call does restore gas to the bucket, but the 20 binary-search iterations consume zero gas-bucket tokens. At the default `requestsPerSecond=500`, an attacker can sustain 500 req/s × 20 unthrottled binary-search EVM executions = **10,000 unaccounted EVM executions/sec**, versus a normal `eth_call` user who gets 500 EVM executions/sec. This is a **~20x amplification** of CPU and memory load per rate-limit token, well exceeding any reasonable threshold. The gas bucket (`gasPerSecond`) provides no protection because binary-search iterations bypass it entirely. [7](#0-6) 

## Likelihood Explanation
No authentication, API key, or special privilege is required. Any external user can POST to `/api/v1/contracts/call` with `{"estimate": true, "gas": 15000000, ...}`. The attack is trivially scriptable, repeatable at full RPS, and requires no on-chain state. The attacker only needs a valid (or zero) contract address. The endpoint is publicly exposed. [10](#0-9) 

## Recommendation
1. **Account for binary-search iterations in the gas bucket.** Pass `estimate=false` to `doProcessCall` inside the binary search, or introduce a separate lightweight gas-accounting path that calls `restoreGasToBucket` for each binary-search iteration.
2. **Alternatively, deduct gas proportionally for estimate requests.** Before entering `binaryGasEstimator.search()`, pre-deduct `maxGasEstimateRetriesCount × scaleGas(params.getGas())` tokens from `gasLimitBucket`, and restore the unused portion afterward.
3. **Reduce `maxGasEstimateRetriesCount` or make it a hard security cap** rather than a purely functional tuning parameter, so operators understand its security implications.
4. **Add a separate RPS throttle for estimate requests** distinct from `eth_call`, since estimate requests are inherently more expensive. [6](#0-5) 

## Proof of Concept
```
# Attacker script (pseudocode)
while True:
    POST /api/v1/contracts/call
    {
      "estimate": true,
      "gas": 15000000,
      "to": "0x0000000000000000000000000000000000000000",
      "data": "<computationally expensive calldata>"
    }
    # Each request: 1 RPS token consumed, up to 20 unthrottled EVM executions triggered
    # At 500 req/s: 10,000 unaccounted EVM executions/sec
```

**Observed behavior:**
- `throttleManager.throttle()` called once per request (`ContractController.java:40`)
- `callContract()` → `doProcessCall(..., false)` for initial call — gas restored (`ContractCallService.java:106`)
- `binaryGasEstimator.search()` calls `doProcessCall(..., true)` up to 20 times — `restoreGasToBucket` skipped (`ContractCallService.java:128-135`)
- Net result: 20 full EVM executions with zero gas-bucket accounting [11](#0-10)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L18-47)
```java
    private static final long GAS_SCALE_FACTOR = 10_000L;

    @Min(0)
    @Max(100)
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

    // Necessary since bucket4j has a max capacity and fill rate of 1 token per nanosecond
    public long getGasPerSecond() {
        return scaleGas(gasPerSecond);
    }

    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L68-73)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;

    // Maximum iteration count for estimate gas' search algorithm
    @Positive
    private int maxGasEstimateRetriesCount = 20;
```
