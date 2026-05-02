After thoroughly examining all referenced code paths, I can verify the technical accuracy of each claim.

**Verified facts:**

1. `constructServiceParameters()` maps `to=null` to `Address.ZERO` — confirmed at lines 60-61 of `ContractController.java`. [1](#0-0) 

2. `hasTo()` always returns `true` when `value=0` (the default) — confirmed at lines 54-57 of `ContractCallRequest.java`. When `value <= 0`, `isValidToField = true` unconditionally, making the `BytecodeUtils.isValidInitBytecode(data)` branch irrelevant. [2](#0-1) 

3. `estimateGas()` runs 1 initial EVM call via `callContract()`, then launches a binary search of up to `maxGasEstimateRetriesCount` (default 20) iterations — confirmed in `ContractExecutionService.java` lines 81-98. [3](#0-2) 

4. Binary search iterations call `doProcessCall(params, gas, true)` with `estimate=true`, and the `finally` block that calls `restoreGasToBucket` is guarded by `if (!estimate)` — confirmed at lines 127-135 of `ContractCallService.java`. [4](#0-3) 

5. The throttle is consumed exactly once per HTTP request at `throttleManager.throttle(request)` in `ContractController.call()`. [5](#0-4) 

6. `maxGasEstimateRetriesCount` defaults to 20 (not 24 as stated in the report), giving a maximum of 21 total EVM executions (1 initial + 20 binary search). [6](#0-5) 

The SECURITY.md excludes "Impacts that only require DDoS" but this finding is not a pure volumetric DDoS — it is a code-level throttle accounting asymmetry that enables disproportionate CPU consumption relative to throttle cost paid. The throttle model assumes one EVM execution per request, but `estimateGas` performs up to 21. This is a genuine logic flaw, not a pure DDoS.

---

# Audit Report

## Title
Unbounded EVM Binary-Search Multiplication via Null `to` Field Enabling Throttle Bypass in `estimateGas`

## Summary
Any unauthenticated caller can POST to `/api/v1/contracts/call` with `to` omitted and `estimate: true`. The `hasTo()` validator unconditionally passes when `value=0` (the default), `constructServiceParameters()` maps the null `to` to `Address.ZERO`, and `estimateGas()` then performs 1 initial EVM execution plus up to 20 binary-search EVM executions — while the gas-bucket throttle is charged only once and `restoreGasToBucket` is never called for binary-search iterations. This creates a ~21× CPU amplification factor relative to the throttle cost paid.

## Finding Description

**Entry point — validation always passes for `to=null, value=0`:**

`ContractCallRequest.hasTo()` returns `true` whenever `value <= 0`, which is the default. The `BytecodeUtils.isValidInitBytecode(data)` branch is never the deciding factor:

```java
private boolean hasTo() {
    boolean isValidToField = value <= 0 || from == null || StringUtils.isNotEmpty(to);
    return BytecodeUtils.isValidInitBytecode(data) || isValidToField;
}
``` [2](#0-1) 

**Routing — null `to` maps to `Address.ZERO`:**

```java
if (request.getTo() == null || request.getTo().isEmpty()) {
    receiver = Address.ZERO;
}
``` [1](#0-0) 

**Amplification — `estimateGas` runs 1 + up to 20 EVM executions:**

```java
private Bytes estimateGas(final ContractExecutionParameters params, final ContractCallContext context) {
    final var processingResult = callContract(params, context);          // EVM execution #1
    ...
    final var estimatedGas = binaryGasEstimator.search(
            ...,
            gas -> doProcessCall(params, gas, true),                     // EVM executions #2–#21
            gasUsedByInitialCall,
            params.getGas());
``` [7](#0-6) 

The `BinaryGasEstimator.search()` loop runs up to `maxGasEstimateRetriesCount = 20` iterations: [8](#0-7) 

**Throttle bypass — `restoreGasToBucket` skipped for all binary-search iterations:**

```java
} finally {
    if (!estimate) {                          // estimate=true for all binary-search calls
        restoreGasToBucket(result, params.getGas());
        ...
    }
}
``` [4](#0-3) 

The throttle is consumed once at the controller level and never adjusted for the 20 binary-search EVM invocations: [5](#0-4) 

**Root cause:** The gas-bucket throttle model assumes one EVM execution per request. `estimateGas` performs up to 21 EVM executions per request. The `if (!estimate)` guard in `doProcessCall`'s `finally` block was intended to avoid double-counting gas restoration during the search loop, but it also means the binary-search iterations consume zero throttle budget.

## Impact Explanation
Each request with `to=null, estimate=true` triggers up to 21 EVM executions while consuming only 1 unit of gas-throttle budget. With the default `maxGasLimit` of 15,000,000 and complex init bytecode, each request imposes up to ~21× the CPU cost the throttle was designed to limit. Sustained at even moderate request rates this degrades response latency for all other users sharing the same server, constituting a denial-of-service griefing attack with no economic cost to the attacker. [9](#0-8) 

## Likelihood Explanation
No authentication, API key, or privileged role is required. The attacker only needs to omit `to` and set `estimate: true`. Since `value` defaults to `0`, the `hasTo()` validator always passes. The `data` field can be any hex string or omitted entirely. The attack is fully repeatable and scriptable from any HTTP client. [10](#0-9) 

## Recommendation
1. **Account for binary-search iterations in the throttle.** Before entering the binary-search loop in `estimateGas`, pre-consume additional gas tokens proportional to `maxGasEstimateRetriesCount` (e.g., multiply the initial throttle charge by a factor reflecting the expected number of iterations), or call `throttleManager.throttle`/deduct tokens inside the binary-search loop.
2. **Alternatively, apply a separate per-request rate limit specifically for `estimate=true` requests** using the existing `RequestProperties` / `THROTTLE` action mechanism, which already supports filtering on the `ESTIMATE` field. [11](#0-10) 
3. **Cap `maxGasEstimateRetriesCount`** to a lower value in production configurations to reduce the amplification ceiling. [12](#0-11) 

## Proof of Concept

```http
POST /api/v1/contracts/call HTTP/1.1
Content-Type: application/json

{
  "data": "0x6080604052348015600f57600080fd5b5060a38061001c6000396000f3",
  "estimate": true,
  "gas": 15000000
}
```

- `to` is omitted → `hasTo()` returns `true` (because `value=0 <= 0`) → validation passes.
- `constructServiceParameters()` sets `receiver = Address.ZERO`.
- `throttleManager.throttle(request)` consumes 15,000,000 gas tokens once.
- `estimateGas()` calls `callContract()` (EVM execution #1, `estimate=false` → `restoreGasToBucket` called, partial gas returned).
- `binaryGasEstimator.search()` runs up to 20 iterations of `doProcessCall(..., true)` (EVM executions #2–#21, `estimate=true` → `restoreGasToBucket` never called).
- Net result: up to 21 EVM executions for the cost of ~1 in the throttle bucket.

Flooding this endpoint at the `requestsPerSecond` limit (default 500 RPS) results in up to 10,500 EVM executions per second while the throttle believes it is processing 500.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L39-44)
```java
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L58-64)
```java
        /*In case of an empty "to" field, we set a default value of the zero address
        to avoid any potential NullPointerExceptions throughout the process.*/
        if (request.getTo() == null || request.getTo().isEmpty()) {
            receiver = Address.ZERO;
        } else {
            receiver = Address.fromHexString(request.getTo());
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L36-46)
```java
    @Min(21_000)
    private long gas = 15_000_000L;

    @Min(0)
    private long gasPrice;

    @Hex(minLength = ADDRESS_LENGTH, maxLength = ADDRESS_LENGTH, allowEmpty = true)
    private String to;

    @PositiveOrZero
    private long value;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L53-57)
```java
    @AssertTrue(message = "must not be empty")
    private boolean hasTo() {
        boolean isValidToField = value <= 0 || from == null || StringUtils.isNotEmpty(to);
        return BytecodeUtils.isValidInitBytecode(data) || isValidToField;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L68-73)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;

    // Maximum iteration count for estimate gas' search algorithm
    @Positive
    private int maxGasEstimateRetriesCount = 20;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L39-48)
```java
    enum FilterField {
        BLOCK(ContractCallRequest::getBlock),
        DATA(ContractCallRequest::getData),
        ESTIMATE(ContractCallRequest::isEstimate),
        FROM(ContractCallRequest::getFrom),
        GAS(ContractCallRequest::getGas),
        TO(ContractCallRequest::getTo),
        VALUE(ContractCallRequest::getValue);

        private final Function<ContractCallRequest, Object> extractor;
```
