All code references have been verified against the actual source. Here is the audit report:

---

Audit Report

## Title
Estimate Calls Bypass Gas Throttle Multiplier: Up to 21x EVM Executions Per Throttle Token

## Summary
`ThrottleManagerImpl.throttle()` consumes throttle tokens based solely on `request.getGas()` without differentiating between `estimate=true` and `estimate=false` calls. An `estimate=true` call triggers one initial EVM execution plus up to 20 binary-search iterations (default `maxGasEstimateRetriesCount=20`), all for the same throttle cost as a single `eth_call`. Any unprivileged user can exploit this to drive up to 21x more EVM computation per throttle token.

## Finding Description

**Throttle entry point** — `ThrottleManagerImpl.throttle()`:

`throttle()` consumes one rate-limit token and `scaleGas(request.getGas())` gas tokens. The `estimate` flag on the request is never consulted. [1](#0-0) 

**Estimate execution path** — `ContractExecutionService.estimateGas()`:

`estimateGas()` first calls `callContract(params, context)` (which internally calls `doProcessCall(params, params.getGas(), false)` — the `false` flag triggers `restoreGasToBucket`). It then invokes `binaryGasEstimator.search()` passing `gas -> doProcessCall(params, gas, true)` — the `true` flag suppresses `restoreGasToBucket` for every binary-search iteration. [2](#0-1) [3](#0-2) 

**Gas restore guard** — `ContractCallService.doProcessCall()`:

`restoreGasToBucket` is only called when `!estimate`. The 20 binary-search iterations pass `estimate=true`, so they are entirely invisible to the throttle system — no tokens consumed, none restored. [4](#0-3) 

**Binary search loop** — `BinaryGasEstimator.search()`:

The loop runs up to `maxGasEstimateRetriesCount` (default 20) iterations, each invoking a full EVM execution via the supplied `call` lambda. [5](#0-4) [6](#0-5) 

**Net effect per request:**

| Call type | Throttle tokens consumed (net) | EVM executions |
|---|---|---|
| `estimate=false` | `scaleGas(gas) − restored_remainder` | 1 |
| `estimate=true` | same as above (initial call restores) | 1 + up to 20 = **21** |

## Impact Explanation

The binary-search loop performs up to 20 additional full EVM executions per request. Each execution involves database I/O, state loading, and CPU-intensive bytecode interpretation. At the default RPS limit of 500 req/s [7](#0-6) 
and `maxGasLimit` of 15,000,000 [8](#0-7) 
a sustained flood of `estimate=true` requests can generate up to 10,500 EVM executions per second instead of 500 — a ~2000% increase in EVM workload. This can exhaust CPU, thread pools, and database connection pools, degrading or denying service to legitimate users. The `gasLimitRefundPercent` default of 100% [9](#0-8) 
means the initial call's gas is almost entirely restored, making the net throttle cost negligible while the binary-search iterations remain completely unaccounted for.

## Likelihood Explanation

The `/api/v1/contracts/call` endpoint is publicly accessible with no authentication. [10](#0-9) 
The `estimate` field is a standard boolean in the JSON body. An attacker needs only to set `"estimate": true` in otherwise valid requests. No special knowledge, credentials, or tooling beyond a standard HTTP client is required. The attack is trivially repeatable and scriptable. The `RequestFilter` system supports filtering on `ESTIMATE` field, but no such filter is configured by default. [11](#0-10) 

## Recommendation

1. **Scale throttle tokens by call type**: In `ThrottleManagerImpl.throttle()`, multiply the gas tokens consumed by a configurable `estimateGasMultiplier` (e.g., `maxGasEstimateRetriesCount + 1 = 21`) when `request.isEstimate()` is `true`.
2. **Restore gas for binary-search iterations**: In `ContractCallService.doProcessCall()`, call `restoreGasToBucket` for binary-search iterations as well, or track cumulative gas consumed across all iterations and restore at the end of `estimateGas()`.
3. **Add a default request filter**: Configure a default `THROTTLE` action on `ESTIMATE=true` requests with a lower per-second rate than regular calls to reflect the higher resource cost.
4. **Expose a separate rate limit**: Add a dedicated `estimateRequestsPerSecond` property analogous to `opcodeRequestsPerSecond` to independently cap estimate traffic. [12](#0-11) 

## Proof of Concept

```bash
# Flood the endpoint with estimate=true requests at the permitted RPS
# Each request triggers up to 21 EVM executions while consuming throttle tokens for only 1

for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d '{
      "to": "<deployed_contract_address>",
      "data": "<calldata_for_expensive_function>",
      "gas": 15000000,
      "estimate": true
    }' &
done
wait
```

Each of the 500 concurrent requests passes `ThrottleManagerImpl.throttle()` consuming `scaleGas(15_000_000)` tokens (same as a regular call), but internally triggers `callContract` (1 EVM execution with gas restored) followed by `binaryGasEstimator.search()` with up to 20 additional `doProcessCall(..., true)` iterations — none of which interact with the throttle bucket. The server processes up to 10,500 full EVM simulations per second while the throttle believes it is processing only 500. [13](#0-12) [14](#0-13)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L68-69)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L72-73)
```java
    @Positive
    private int maxGasEstimateRetriesCount = 20;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L22-22)
```java
    private float gasLimitRefundPercent = 100;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L42-42)
```java
        ESTIMATE(ContractCallRequest::isEstimate),
```
