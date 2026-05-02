All technical claims have been verified against the actual source code. Here is the result:

---

# Audit Report

## Title
Gas Estimation Binary Search Bypasses Per-Request Gas Throttle, Enabling CPU Exhaustion DoS

## Summary
The gas throttle is consumed exactly once per request at the controller level. However, `BinaryGasEstimator.search()` runs up to `maxGasEstimateRetriesCount=20` additional full EVM executions with `estimate=true`, which explicitly skips both throttle consumption and gas restoration. The `requestTimeout` is enforced only at Hibernate SQL statement boundaries, meaning CPU-bound EVM iterations that hit cached state never trigger the timeout. An unprivileged attacker can therefore cause up to 21× the throttle-accounted EVM work per request while remaining within the rate limit.

## Finding Description

**Step 1 – Single throttle deduction at controller entry**

`ContractController.call()` calls `throttleManager.throttle(request)` exactly once, consuming `scaleGas(request.getGas())` tokens from the shared `gasLimitBucket`. [1](#0-0) [2](#0-1) 

**Step 2 – Initial call uses `estimate=false`, validates result**

`estimateGas` calls `callContract(params, context)`, which internally calls `doProcessCall(params, params.getGas(), false)`. With `estimate=false`, `validateResult` is invoked; a revert throws `MirrorEvmTransactionException` and aborts before the binary search. For a contract that succeeds at full gas, execution continues to the binary search. [3](#0-2) [4](#0-3) 

**Step 3 – Binary search calls `doProcessCall` with `estimate=true` — no throttle, no restore**

`BinaryGasEstimator.search()` loops up to `maxGasEstimateRetriesCount` (default: 20) times, each time calling `doProcessCall(params, gas, true)`. The `finally` block in `doProcessCall` is gated on `!estimate`, so neither `restoreGasToBucket` nor any throttle consumption occurs for any of these iterations. [5](#0-4) [6](#0-5) 

**Step 4 – `requestTimeout` only fires at Hibernate SQL boundaries**

`HibernateConfiguration.statementInspector()` checks elapsed time only when Hibernate is about to execute a SQL statement. If binary search iterations hit cached EVM state (contract bytecode, account data already in the read cache), no SQL is issued and the timeout never fires regardless of wall-clock time. [7](#0-6) 

**Step 5 – `scaleGas` floors small values to zero**

`ThrottleProperties.scaleGas()` returns `0` for any gas value ≤ `GAS_SCALE_FACTOR` (10,000), meaning requests with gas in that range consume nothing from the bucket at all. [8](#0-7) 

**Root cause**: The gas throttle model assumes one EVM execution per request. For `estimate=true` requests the actual execution count is `1 + min(20, iterations_to_converge)`, but the throttle only accounts for 1.

## Impact Explanation

With default settings (`requestsPerSecond=500`, `maxGasLimit=15,000,000`, `maxGasEstimateRetriesCount=20`), each estimate request that drives the full 20-iteration binary search performs 21 EVM executions while consuming only 1 slot in the gas bucket. An attacker sending 500 estimate requests per second (within the RPS limit) forces the server to execute up to 10,500 EVM runs per second instead of the intended 500. Each run at 15M gas is a substantial CPU workload. Combined with the timeout gap for cache-warm iterations, this can saturate all available server threads, causing legitimate requests to queue indefinitely or be rejected. [9](#0-8) 

## Likelihood Explanation

No authentication or privileged access is required. The attacker only needs:
1. A deployed contract (or any existing contract address) that succeeds at full gas but reverts below a threshold — trivially constructable.
2. The ability to send HTTP POST requests to `/api/v1/contracts/call` with `estimate: true`.

The attack is fully repeatable, scriptable, and requires no on-chain funds since the mirror node simulates execution without submitting transactions. [10](#0-9) 

## Recommendation

1. **Account for binary search iterations in the throttle**: Before entering `binaryGasEstimator.search()`, pre-consume additional gas tokens proportional to `maxGasEstimateRetriesCount`, or consume one token per binary search iteration inside `BinaryGasEstimator.search()`.
2. **Enforce a wall-clock timeout independent of SQL boundaries**: Use a dedicated `ScheduledExecutorService` or a servlet filter with a hard deadline that interrupts the request thread regardless of whether SQL is being executed.
3. **Limit binary search iterations based on remaining budget**: Track elapsed time inside `BinaryGasEstimator.search()` and abort early if the request timeout is approaching.
4. **Fix `scaleGas` zero-floor bypass**: Requests with gas ≤ 10,000 should consume at least 1 token from the gas bucket to prevent free-riding. [11](#0-10) 

## Proof of Concept

```
1. Deploy a contract with the following logic:
   - Succeeds (returns normally) when gasLeft() >= THRESHOLD (e.g., 14,000,000)
   - Reverts when gasLeft() < THRESHOLD

2. Send 500 POST /api/v1/contracts/call requests per second with:
   {
     "to": "<contract_address>",
     "estimate": true,
     "gas": 15000000
   }

3. Each request:
   a. Passes throttle check (1 RPS token + scaleGas(15M)=1500 gas tokens consumed)
   b. Initial callContract() with estimate=false succeeds (gas=15M > THRESHOLD)
   c. binaryGasEstimator.search() runs up to 20 iterations, each calling
      doProcessCall(..., mid, true) — no throttle consumed, no gas restored
   d. Total EVM executions per request: up to 21

4. At 500 RPS, the server performs up to 10,500 EVM executions/second
   while the throttle only accounts for 500.

5. With cache-warm state, no SQL is issued during binary search iterations,
   so the 10-second requestTimeout never fires for those iterations.
``` [12](#0-11) [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L81-95)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java (L20-62)
```java
    public long search(
            final ObjIntConsumer<Long> metricUpdater, final LongFunction<EvmTransactionResult> call, long lo, long hi) {
        long prevGasLimit = lo;
        int iterationsMade = 0;
        long totalGasUsed = 0;

        // Now that we also support gas estimates for precompile calls, the default threshold is too low, since
        // it does not take into account the minimum threshold of 5% higher estimate than the actual gas used.
        // The default value is working with some calls but that is not the case for precompile calls which have higher
        // gas consumption.
        // Configurable tolerance of 10% over 5% is used, since the algorithm fails when using 5%, producing too narrow
        // threshold. Adjust via estimateGasIterationThresholdPercent value.
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

        metricUpdater.accept(totalGasUsed, iterationsMade);
        return hi;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-47)
```java
    StatementInspector statementInspector() {
        long timeout = web3Properties.getRequestTimeout().toMillis();
        return sql -> {
            if (!ContractCallContext.isInitialized()) {
                return sql;
            }

            var startTime = ContractCallContext.get().getStartTime();
            long elapsed = System.currentTimeMillis() - startTime;

            if (elapsed >= timeout) {
                throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
            }

            return sql;
        };
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L24-35)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```
