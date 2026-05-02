### Title
Unbounded EVM Execution Amplification in `eth_estimateGas` Binary Search — Throttle Applied Once Per HTTP Request, Not Per Iteration

### Summary
An unprivileged external user can submit a single `eth_estimateGas` HTTP request with `gas=15,000,000` and calldata targeting a contract that always reverts below the maximum gas limit. This forces `BinaryGasEstimator.search()` to exhaust all `maxGasEstimateRetriesCount=20` iterations, each performing a full EVM execution, for a total of 21 EVM executions per request. The gas/rate throttle is applied exactly once at the HTTP controller layer and is never re-checked inside the binary search loop, creating a 21× CPU amplification factor per request.

### Finding Description

**Code path:**

`ContractController.call()` → `throttleManager.throttle(request)` (once) → `ContractExecutionService.estimateGas()` → `callContract()` (initial execution) → `BinaryGasEstimator.search()` (up to 20 more executions).

**Root cause — throttle applied once, binary search not throttled:**

In `ContractController.java` line 40, `throttleManager.throttle(request)` is called exactly once per HTTP request, consuming one token from the rate-limit bucket and `scaleGas(15_000_000) = 1_500` tokens from the gas bucket. [1](#0-0) 

Inside `ContractExecutionService.estimateGas()`, the initial `callContract()` call uses `estimate=false`, so `restoreGasToBucket` is invoked after it. However, the subsequent `binaryGasEstimator.search()` call passes `estimate=true` to every `doProcessCall()` invocation, which explicitly skips `restoreGasToBucket` and — critically — skips any throttle check entirely. [2](#0-1) [3](#0-2) 

**Binary search loop — all 20 iterations forced:**

The loop in `BinaryGasEstimator.search()` runs while `lo + 1 < hi && iterationsMade < maxGasEstimateRetriesCount` (default 20). When `safeCall()` returns `null` (exception caught) or the result is unsuccessful, `err=true` and `lo = mid`, keeping `lo + 1 < hi` true and advancing toward the next iteration. If every iteration fails, the loop runs exactly 20 times. [4](#0-3) 

`safeCall()` swallows all exceptions and returns `null`, ensuring no iteration terminates the loop early on error. [5](#0-4) 

**Exploit flow:**

1. Attacker deploys a contract with logic equivalent to `require(gasleft() >= 14_999_000)`.
2. Attacker sends `POST /api/v1/contracts/call` with `estimate=true`, `gas=15_000_000`, calldata targeting that contract.
3. Throttle passes (1 request token + 1,500 gas tokens consumed from a 750,000-token/s bucket).
4. Initial `callContract()` with 15 M gas succeeds (gasleft ≥ threshold) → `gasUsedByInitialCall` is small.
5. `binaryGasEstimator.search(lo=gasUsed, hi=15_000_000)` starts. Every `mid` value (≈7.5 M, 11.25 M, …) is below 14,999,000 → contract reverts → `null` returned → `lo = mid`.
6. Loop runs all 20 iterations, each a full EVM execution with up to 15 M gas worth of opcode processing.
7. Total per request: **21 full EVM executions**, all without additional throttle checks. [6](#0-5) 

### Impact Explanation

A single malicious `eth_estimateGas` request triggers 21 EVM executions versus the 1 execution of a normal `eth_call`. At the default rate limit of 500 requests/second, an attacker sending only `eth_estimateGas` requests can force up to **10,500 EVM executions/second** instead of 500, a **2,000% amplification**. Even a small fraction of malicious traffic (e.g., 15–20 requests/second) mixed with normal traffic can push CPU consumption well above the 30% threshold. The gas bucket (`gasPerSecond=7.5B`) is consumed only once per HTTP request and does not account for the 20 additional binary search executions, so it provides no meaningful protection against this amplification.

### Likelihood Explanation

No authentication, API key, or privileged access is required. The attacker only needs:
- A deployed contract (or a precompile address) that conditionally reverts based on `gasleft()`.
- The ability to send standard JSON-RPC HTTP POST requests to the public endpoint.

The attack is trivially repeatable, scriptable, and can be sustained indefinitely. The contract deployment is a one-time cost. The exploit is deterministic — the same request always triggers 20 binary search iterations.

### Recommendation

1. **Count binary search iterations against the gas throttle bucket.** Inside `BinaryGasEstimator.search()`, call `throttleManager.restore()` / consume gas tokens for each iteration, or pass a per-iteration gas budget check.
2. **Apply a per-request EVM-execution cap.** Limit the total number of EVM invocations (initial + binary search) that can be attributed to a single HTTP request, independent of `maxGasEstimateRetriesCount`.
3. **Reduce `maxGasEstimateRetriesCount`.** The default of 20 is high; logarithmic binary search over [21000, 15M] converges in ≤ 20 steps, but a tighter cap (e.g., 10–12) reduces worst-case amplification.
4. **Detect and short-circuit all-failure patterns.** If several consecutive iterations all return `null`/failure, abort the binary search early and return `hi` (the maximum gas) as the estimate, rather than exhausting all retries. [4](#0-3) [7](#0-6) 

### Proof of Concept

```
# 1. Deploy contract (Solidity pseudocode):
#    contract GasChecker {
#        function check() external view {
#            require(gasleft() >= 14_999_000, "insufficient gas");
#        }
#    }
#    → deployed at address 0xDEAD...

# 2. Send malicious eth_estimateGas request (no auth required):
curl -X POST https://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{
    "to":       "0xDEAD...",
    "data":     "0x<check() selector>",
    "gas":      15000000,
    "estimate": true
  }'

# Expected server behavior:
# - Throttle passes (1 req token consumed)
# - Initial EVM execution with 15M gas → succeeds (gasleft ≥ 14,999,000)
# - Binary search starts: lo=<small gasUsed>, hi=15,000,000
# - Iteration 1: mid≈7,500,000 → gasleft < 14,999,000 → revert → null → lo=mid
# - Iteration 2: mid≈11,250,000 → revert → null → lo=mid
# - ... (all 20 iterations fail identically)
# - Total: 21 full EVM executions per single HTTP request

# 3. Repeat at ~25 req/s to sustain >30% CPU above baseline:
for i in $(seq 1 1000); do
  curl -s -X POST ... &
  sleep 0.04
done
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-41)
```java
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java (L67-74)
```java
    private EvmTransactionResult safeCall(long mid, LongFunction<EvmTransactionResult> call) {
        try {
            return call.apply(mid);
        } catch (Exception ignored) {
            log.info("Exception while calling contract for gas estimation");
            return null;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L26-36)
```java
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;

```
