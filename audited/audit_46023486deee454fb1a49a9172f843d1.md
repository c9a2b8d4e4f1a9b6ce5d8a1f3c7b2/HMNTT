### Title
Unthrottled Binary Gas Estimator Amplification via Historical Block Estimation

### Summary
An unprivileged user can POST to `/api/v1/contracts/call` with `estimate=true`, a historical block number, and `gas=15000000` (the maximum). The throttle mechanism consumes tokens only once per request at the start, but the binary gas estimator then executes up to 20 additional EVM iterations against historical state without consuming any further throttle tokens. This creates a resource amplification factor of up to 21× per request.

### Finding Description

**Entry point** — `ContractController.java` lines 38–51 (`call()`): [1](#0-0) 

The throttle is consumed **once** at request entry via `throttleManager.throttle(request)`, which deducts `scaleGas(request.getGas())` (i.e., 15 M gas tokens) from the `gasLimitBucket` and 1 token from the `rateLimitBucket`. [2](#0-1) 

Control then flows to `ContractExecutionService.estimateGas()`, which:
1. Performs an initial `callContract()` call (with `estimate=false`, so gas restoration runs once).
2. Passes the result to `BinaryGasEstimator.search()` with `lo = gasUsedByInitialCall` and `hi = 15_000_000`. [3](#0-2) 

`BinaryGasEstimator.search()` loops up to `maxGasEstimateRetriesCount = 20` times, calling `doProcessCall(params, gas, true)` each iteration: [4](#0-3) 

Inside `doProcessCall`, when `estimate=true`, the `restoreGasToBucket` path is **skipped entirely** — meaning neither gas consumption nor restoration is tracked for any of the 20 binary search iterations: [5](#0-4) 

**Root cause**: The throttle gate is a one-time check at the HTTP layer. The binary search loop is entirely inside the service layer and executes up to 20 full EVM invocations with zero additional throttle accounting. The `maxGasEstimateRetriesCount = 20` cap is a correctness bound, not a resource-protection bound. [6](#0-5) 

For historical blocks, each iteration additionally triggers a time-travel database query to reconstruct state at the requested block, multiplying I/O cost. [7](#0-6) 

### Impact Explanation
Each request with `estimate=true` + historical block + `gas=15_000_000` causes up to **21 EVM executions** (1 initial + 20 binary search) while consuming only 1 request token and 15 M gas tokens from the throttle. An attacker operating at the rate limit can therefore drive actual EVM execution and historical-state I/O at 21× the rate the throttle was designed to permit. Under sustained load this exhausts CPU and database connection pools, degrading or denying service to legitimate users.

### Likelihood Explanation
No authentication or special privilege is required — the endpoint is public. The attacker needs only a standard HTTP client. The attack is trivially repeatable and scriptable. The worst-case amplification (20 iterations) is reliably triggered by supplying a very small initial gas usage relative to the 15 M ceiling, which maximises the binary search depth. Historical block support is documented in the OpenAPI spec, so the parameter combination is publicly known. [8](#0-7) 

### Recommendation
1. **Account for binary search multiplier in throttle**: Before entering `estimateGas`, pre-consume `maxGasEstimateRetriesCount × gas` tokens (or a configurable fraction) from the gas bucket, restoring unused tokens after the search completes.
2. **Track per-iteration gas in the bucket**: Pass the throttle manager into `BinaryGasEstimator.search()` and call `tryConsume` for each iteration's `mid` gas value, failing fast if the bucket is exhausted.
3. **Apply a stricter rate limit for estimate+historical combinations**: Add a dedicated `RequestProperties` filter in `ThrottleProperties` that applies a lower per-second cap when both `estimate=true` and a non-latest block are present.
4. **Cap historical estimate gas**: Enforce a lower `maxGasLimit` for historical estimation requests than for latest-block calls.

### Proof of Concept
```bash
# Repeat at the maximum allowed request rate
while true; do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{
      "block": "0x1000000",
      "to": "0x0000000000000000000000000000000000000001",
      "gas": 15000000,
      "estimate": true
    }' &
done
```
Each request passes the single throttle check (1 req token + 15 M gas tokens) and then triggers up to 21 EVM executions against historical state block `0x1000000`. At the default rate limit, the server processes 21× more EVM work than the throttle was designed to allow, leading to CPU saturation and database connection exhaustion.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L67-69)
```java
    // Maximum iteration count for estimate gas' search algorithm
    @Positive
    private int maxGasEstimateRetriesCount = 20;
```

**File:** rest/api/v1/openapi.yml (L461-467)
```yaml
  /api/v1/contracts/call:
    post:
      summary: Invoke a smart contract
      description:
        Returns a result from EVM execution such as cost-free execution of read-only smart contract queries, gas estimation, and transient simulation of read-write operations. If the `estimate` field is set to true gas estimation is executed.
        This API can process calls against the `latest` block or specific historical blocks when a hexadecimal or decimal block number is provided in the `block` field.
      operationId: contractCall
```
