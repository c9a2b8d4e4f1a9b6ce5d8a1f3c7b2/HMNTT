### Title
Gas Throttle Amplification via Binary Search in `estimateGas`: Up to 21x EVM Executions Per Single Throttle Token

### Summary
An unprivileged external user can send `eth_estimateGas` requests (`estimate=true`) that trigger a binary search loop executing up to 20 additional EVM calls inside `BinaryGasEstimator.search()`, on top of the initial `callContract()` invocation, all against a single throttle check. Because `restoreGasToBucket` and all throttle accounting are gated on `!estimate` in `doProcessCall()`, the binary search iterations consume zero additional throttle tokens while performing full EVM execution, amplifying node resource consumption by up to 21x per gas token deducted from `gasLimitBucket`.

### Finding Description

**Throttle check — one-time, at request boundary:**
`ThrottleManager.throttle(request)` is invoked once per HTTP request (in the filter/interceptor layer) consuming gas tokens from `gasLimitBucket` based on the request's gas limit.

**`ContractExecutionService.processCall()` — estimate branch:** [1](#0-0) 

When `params.isEstimate()` is `true`, `estimateGas()` is called.

**`estimateGas()` — two-phase execution:** [2](#0-1) 

Phase 1: `callContract(params, context)` → internally calls `doProcessCall(params, params.getGas(), false)` — `estimate=false`, so `restoreGasToBucket` IS called here.

Phase 2: `binaryGasEstimator.search(...)` with lambda `gas -> doProcessCall(params, gas, true)` — `estimate=true` for every iteration.

**`BinaryGasEstimator.search()` — up to `maxGasEstimateRetriesCount` iterations:** [3](#0-2) 

The loop runs `while (lo + 1 < hi && iterationsMade < properties.getMaxGasEstimateRetriesCount())`, executing a full EVM call each iteration via `safeCall`.

**`doProcessCall()` — throttle accounting gated on `!estimate`:** [4](#0-3) 

```java
} finally {
    if (!estimate) {
        restoreGasToBucket(result, params.getGas());
        if (result != null) {
            updateMetrics(params, result.gasUsed(), 1, status);
        }
    }
}
```

All 20 binary search iterations pass `estimate=true`, so `restoreGasToBucket` is never called and no additional gas is consumed from the bucket. The bucket sees exactly one deduction for the entire request regardless of how many EVM executions occur.

**`gasLimitBucket` — single-dimension throttle:** [5](#0-4) 

The bucket is filled at `gasPerSecond` (default 7.5 billion, scaled to 750,000 tokens). It has no awareness of whether a request is an estimate that will multiply EVM work.

**Root cause:** The throttle model assumes 1 request = 1 EVM execution. For estimate requests, the actual ratio is 1 request = 1 + up to 20 EVM executions. The `!estimate` guard that skips `restoreGasToBucket` was intended to avoid double-accounting gas restoration inside the search loop, but it also means the binary search iterations are completely invisible to the throttle.

### Impact Explanation

With `maxGasEstimateRetriesCount = 20` and maximum gas of 15,000,000:
- A normal `eth_call` consumes 1 throttle token → 1 EVM execution.
- An `eth_estimateGas` consumes 1 throttle token → up to 21 EVM executions (1 initial + 20 binary search).

An attacker sending estimate requests at the maximum allowed rate saturates the node's EVM execution capacity at 21x the rate the throttle was designed to permit. This directly increases CPU, memory, and I/O consumption by over 2000% relative to the throttle's intended ceiling — far exceeding the 30% threshold. Under sustained attack, legitimate `eth_call` requests will be starved or severely delayed.

### Likelihood Explanation

- **No authentication required.** `eth_estimateGas` is a standard, publicly accessible JSON-RPC endpoint.
- **No special contract needed.** Any deployed contract with a non-trivial function (e.g., a loop or storage write) maximizes binary search iterations.
- **Trivially automatable.** A single script sending concurrent `eth_estimateGas` requests with `gas=15000000` is sufficient.
- **Repeatable indefinitely.** The throttle refills every second; the attacker simply re-sends at the refill rate.

### Recommendation

1. **Account for estimate multiplier in throttle consumption.** When `isEstimate=true`, consume `gas * maxGasEstimateRetriesCount` tokens from `gasLimitBucket` upfront, or consume one token per binary search iteration inside `doProcessCall` regardless of the `estimate` flag.
2. **Add a separate rate limit for estimate requests.** Introduce a dedicated bucket (similar to `opcodeRateLimitBucket`) that limits `eth_estimateGas` requests per second independently of `eth_call`.
3. **Cap binary search iterations more aggressively.** Reduce `maxGasEstimateRetriesCount` or make it configurable with a lower default, and document the resource amplification factor.
4. **Restore gas to bucket for estimate iterations too.** Remove the `!estimate` guard around `restoreGasToBucket` so unused gas from each binary search iteration is returned, preventing the bucket from being drained faster than intended.

### Proof of Concept

**Preconditions:**
- A running mirror node web3 service with default throttle settings.
- Any deployed smart contract with a moderately expensive function (e.g., iterates over storage).

**Steps:**
```bash
# Send concurrent eth_estimateGas requests at the maximum allowed rate
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>:8545 \
    -H "Content-Type: application/json" \
    -d '{
      "jsonrpc":"2.0",
      "method":"eth_estimateGas",
      "params":[{
        "to":"<contract_address>",
        "data":"<expensive_function_selector>",
        "gas":"0xE4E1C0"
      }],
      "id":1
    }' &
done
wait
```

**Result:**
- Each request passes the single throttle check (consuming ~1,500 scaled gas tokens from `gasLimitBucket`).
- Each request triggers up to 21 full EVM executions inside `estimateGas()` + `BinaryGasEstimator.search()`.
- Node CPU/memory consumption rises to ~21x what the throttle was designed to allow.
- Concurrent legitimate `eth_call` requests experience severe latency or throttle rejection while the attacker's estimate requests consume all available EVM execution capacity.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L53-54)
```java
                if (params.isEstimate()) {
                    result = estimateGas(params, ctx);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L34-45)
```java
    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }
```
