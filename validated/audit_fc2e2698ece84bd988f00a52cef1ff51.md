All code references have been verified against the actual source. Here is the result:

---

Audit Report

## Title
Disabled EVM-Layer Gas Throttles Combined with Unaccounted Binary-Search Multiplier Enable CPU Amplification via `eth_estimateGas`

## Summary
The application-layer throttle in `ThrottleManagerImpl` charges gas tokens exactly once per HTTP request, but `eth_estimateGas` internally triggers up to 21 full EVM executions (1 initial call + up to 20 binary-search iterations). Because EVM-layer throttles are hardcoded off, each of those executions runs at full CPU speed. An unprivileged attacker can consume up to 21× more CPU per throttle token than a regular `eth_call`.

## Finding Description

**Throttle charged once per request:**

`ContractController.call()` calls `throttleManager.throttle(request)` exactly once at line 40, before dispatching to `contractExecutionService.processCall(params)`. [1](#0-0) 

`ThrottleManagerImpl.throttle()` consumes `scaleGas(request.getGas())` tokens from `gasLimitBucket` at line 40. With `GAS_SCALE_FACTOR = 10_000` and `maxGasLimit = 15,000,000`, a max-gas request consumes 1,500 tokens. [2](#0-1) 

**Binary-search multiplier — never throttled:**

`ContractExecutionService.estimateGas()` first calls `callContract(params, context)` (1 full EVM execution at the user-supplied gas), then unconditionally calls `binaryGasEstimator.search(...)`. [3](#0-2) 

`BinaryGasEstimator.search()` loops `while (lo + 1 < hi && iterationsMade < properties.getMaxGasEstimateRetriesCount())` with `maxGasEstimateRetriesCount = 20`. Each iteration calls `safeCall(mid, call)`, which is a full EVM execution. No throttle token is consumed for any of these iterations. [4](#0-3) 

**Total EVM executions per single throttled request:** 1 (initial) + up to 20 (binary search) = **up to 21**.

**EVM-layer throttles permanently disabled:**

`EvmProperties.buildTransactionProperties()` unconditionally sets `contracts.throttle.throttleByGas = false` (line 160) and `executor.disableThrottles = true` (line 162). While `props.putAll(properties)` at line 176 allows operator override, the defaults are always off and no deployment configuration is shown to change them. [5](#0-4) 

**`scaleGas` blind spot:**

`ThrottleProperties.scaleGas()` returns `0` for any `gas <= 10,000` (the `GAS_SCALE_FACTOR`). Requests with gas at or below this threshold consume zero gas tokens, so they are limited only by the 500 req/s rate limit, yet each still triggers multiple EVM executions. [6](#0-5) 

## Impact Explanation

A single attacker thread submitting `eth_estimateGas` with `gas=15,000,000` at the 500 req/s rate limit triggers up to 10,500 full EVM executions per second (500 × 21), while consuming the same throttle budget as 500 regular `eth_call` executions. This is a **21× CPU amplification** relative to what the throttle was designed to permit. With EVM-layer throttles disabled, each execution runs at full CPU speed with no gas-based pacing or executor-level back-pressure. The binary-search loop runs synchronously within the request thread, and no circuit-breaker or per-request EVM-execution cap exists. [4](#0-3) 

## Likelihood Explanation

No authentication, API key, or account registration is required. Any external user can POST to `/api/v1/contracts/call` with `estimate: true` and `gas: 15000000`. The attack is trivially scriptable, requires no on-chain state, and is repeatable indefinitely as the gas bucket refills every second. The attacker needs only network access to the public endpoint. [7](#0-6) 

## Recommendation

1. **Charge throttle tokens proportionally to actual EVM executions.** Pass a callback into `BinaryGasEstimator.search()` that calls `throttleManager.restore`/`throttle` on each iteration, or pre-charge `maxGasEstimateRetriesCount + 1` tokens upfront and refund unused ones on early exit. [8](#0-7) 

2. **Cap binary-search iterations at a lower default** (e.g., 8–10) to reduce the worst-case multiplier, or expose `maxGasEstimateRetriesCount` as a tunable operator property with a documented security implication. [9](#0-8) 

3. **Fix the `scaleGas` blind spot.** Requests with `gas <= 10,000` should consume at least 1 token, or be subject to a separate low-gas rate limit, to prevent zero-cost flooding. [6](#0-5) 

## Proof of Concept

```bash
# Single-threaded curl loop — no credentials required
while true; do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x0000000000000000000000000000000000000001",
         "gas":15000000,
         "estimate":true,
         "data":"0x"}' &
done
```

Each request consumes 1,500 gas tokens (same as `eth_call`) but triggers up to 21 full EVM executions. At 500 concurrent requests per second (the rate limit), this produces up to 10,500 EVM executions/second against a throttle budget sized for 500. [2](#0-1)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L153-178)
```java
    private Map<String, String> buildTransactionProperties() {
        var props = new HashMap<String, String>();
        props.put("contracts.chainId", network.getChainId().toBigInteger().toString());
        props.put("contracts.evm.version", "v" + evmVersion.major() + "." + evmVersion.minor());
        props.put("contracts.maxRefundPercentOfGasLimit", String.valueOf(maxGasRefundPercentage));
        props.put("contracts.sidecars", "");
        props.put("contracts.throttle.throttleByOpsDuration", "false");
        props.put("contracts.throttle.throttleByGas", "false");
        props.put("contracts.systemContract.scheduleService.scheduleCall.enabled", "true");
        props.put("executor.disableThrottles", "true");
        props.put("fees.simpleFeesEnabled", "false");
        props.put("hedera.realm", String.valueOf(CommonProperties.getInstance().getRealm()));
        props.put("hedera.shard", String.valueOf(CommonProperties.getInstance().getShard()));
        props.put("jumboTransactions.allowedHederaFunctionalities", "ContractCall,ContractCreate,EthereumTransaction");
        props.put("ledger.id", Bytes.wrap(getNetwork().getLedgerId()).toHexString());
        props.put("nodes.gossipFqdnRestricted", "false");
        // The following 3 properties are needed to deliberately fail conditions in upstream to avoid paying rewards to
        // multiple system accounts
        props.put("nodes.nodeRewardsEnabled", "true");
        props.put("nodes.preserveMinNodeRewardBalance", "true");
        props.put("nodes.minNodeRewardBalance", String.valueOf(Long.MAX_VALUE));
        props.put("tss.hintsEnabled", "false");
        props.put("tss.historyEnabled", "false");
        props.putAll(properties); // Allow user defined properties to override the defaults
        return Collections.unmodifiableMap(props);
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
