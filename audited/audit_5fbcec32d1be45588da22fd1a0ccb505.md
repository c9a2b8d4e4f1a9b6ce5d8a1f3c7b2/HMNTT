I have all the information needed. Let me synthesize the full picture.

**Key code facts:**

1. `ContractCallContext.startTime` is `final`, set once at construction, never reset — `reset()` only clears `writeCache`. [1](#0-0) [2](#0-1) 

2. `statementInspector()` measures elapsed time from that original `startTime` and throws `QueryTimeoutException` when `elapsed >= timeout` (default 10 s). [3](#0-2) 

3. `BinaryGasEstimator.search()` loops up to `maxGasEstimateRetriesCount = 20` times, calling `safeCall()` each iteration. [4](#0-3) [5](#0-4) 

4. **`safeCall()` catches `Exception`** — which includes Spring's `QueryTimeoutException` (a `RuntimeException`). When the timeout fires mid-iteration, the exception is silently swallowed and `null` is returned, and the loop continues. [6](#0-5) 

5. `estimateGas()` first calls `callContract()` (initial call, not in `safeCall`), then feeds the result into `binaryGasEstimator.search()`. [7](#0-6) 

---

### Title
`BinaryGasEstimator.safeCall()` Silently Swallows `QueryTimeoutException`, Allowing Gas Estimation to Exceed `requestTimeout`

### Summary
The `safeCall()` method in `BinaryGasEstimator` catches all `Exception` types, including the `QueryTimeoutException` thrown by the Hibernate `statementInspector` when the per-request timeout is reached. Because the exception is swallowed and the binary search loop continues, an unprivileged attacker can submit a crafted `eth_estimateGas` request that causes EVM execution to run well past the configured `requestTimeout`, consuming server-thread and DB resources beyond the intended bound.

### Finding Description

**Code path:**

1. `ContractExecutionService.processCall()` calls `ContractCallContext.run(ctx -> ...)`, creating a new `ContractCallContext` whose `startTime` is set once and never changed.
2. Because `params.isEstimate()` is true, `estimateGas(params, ctx)` is called.
3. `estimateGas()` first calls `callContract(params, context)` — the initial EVM execution — which is **not** wrapped in `safeCall`, so a timeout here would propagate normally.
4. If the initial call succeeds with `gasUsedByInitialCall < params.getGas()`, `binaryGasEstimator.search()` is invoked with `lo = gasUsedByInitialCall`, `hi = params.getGas()` (up to 15 M), and up to 20 iterations.
5. Each iteration calls `safeCall(mid, call)`:

```java
// BinaryGasEstimator.java lines 67-74
private EvmTransactionResult safeCall(long mid, LongFunction<EvmTransactionResult> call) {
    try {
        return call.apply(mid);
    } catch (Exception ignored) {          // ← catches QueryTimeoutException
        log.info("Exception while calling contract for gas estimation");
        return null;
    }
}
```

6. Inside each iteration, `doProcessCall()` → `transactionExecutionService.execute()` triggers EVM execution and DB reads. The Hibernate `statementInspector` fires before each SQL statement:

```java
// HibernateConfiguration.java lines 38-43
var startTime = ContractCallContext.get().getStartTime();
long elapsed = System.currentTimeMillis() - startTime;
if (elapsed >= timeout) {
    throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
}
```

7. Once `elapsed >= timeout`, every subsequent DB query throws `QueryTimeoutException`. But `safeCall` catches it, returns `null`, and the loop continues for all remaining iterations (up to 20 total).

**Root cause:** `safeCall` was introduced to handle modularized-service exceptions gracefully, but its overly broad `catch (Exception ignored)` also neutralises the timeout enforcement mechanism. The `statementInspector` correctly fires, but its signal is discarded.

**Failed assumption:** The design assumes that once `QueryTimeoutException` is thrown, the request terminates. Instead, the exception is absorbed and the binary search continues consuming CPU and DB connections.

### Impact Explanation

Each post-timeout iteration still executes EVM bytecode (CPU-bound, not DB-gated) before hitting the first SQL statement. For contracts involving expensive precompile operations or tight computation loops, this pre-DB phase can take hundreds of milliseconds per iteration. With up to 20 iterations and a 10-second timeout, the actual wall-clock time per request can reach 10 s + (20 × per-iteration EVM setup time). At 500 ms per iteration, that is 10 s + 10 s = 20 s — a 100% overshoot. Concurrent exploitation of this path ties up HTTP worker threads and DB connection-pool slots for twice the intended duration, directly increasing node resource consumption well beyond 30%.

### Likelihood Explanation

No authentication or special privilege is required — `eth_estimateGas` is a standard, publicly accessible JSON-RPC endpoint. The attacker only needs to deploy (or reference an existing) contract that:
- Succeeds with the full gas limit (so the binary search is entered)
- Performs expensive computation before its first storage read in each call

Both conditions are trivially achievable with a contract containing a tight arithmetic or hashing loop followed by a single `SLOAD`. The attack is repeatable and can be parallelised across many concurrent connections.

### Recommendation

1. **Do not catch `QueryTimeoutException` in `safeCall`**: Rethrow it (or any `DataAccessException`) so the binary search loop terminates immediately when the timeout fires:

```java
private EvmTransactionResult safeCall(long mid, LongFunction<EvmTransactionResult> call) {
    try {
        return call.apply(mid);
    } catch (QueryTimeoutException | DataAccessException e) {
        throw e;  // propagate timeout/DB errors
    } catch (Exception ignored) {
        log.info("Exception while calling contract for gas estimation");
        return null;
    }
}
```

2. **Add an explicit wall-clock guard in the binary search loop** in `BinaryGasEstimator.search()` that checks elapsed time against `requestTimeout` at the top of each iteration and breaks early, independent of DB activity.

3. **Enforce the timeout on EVM execution itself**, not only at the DB layer, so that CPU-bound EVM loops are also bounded.

### Proof of Concept

**Preconditions:**
- A deployed contract `GasHog` whose function `burn()` executes ~14 M gas of tight arithmetic (no storage reads) and then reads one storage slot.
- Default config: `requestTimeout = 10s`, `maxGasEstimateRetriesCount = 20`, `maxGasLimit = 15_000_000`.

**Steps:**

1. Call `eth_estimateGas` with `{ "to": "<GasHog>", "data": "<burn() selector>", "gas": "0xE4E1C0" }` (15 M gas).
2. The initial `callContract()` succeeds, using ~14 M gas; `lo = 14_000_000`, `hi = 15_000_000`.
3. The binary search enters with ~20 possible iterations.
4. Each iteration executes ~500 ms of EVM arithmetic before the first `SLOAD` (DB query).
5. After ~10 s total, the `statementInspector` throws `QueryTimeoutException` inside iteration N.
6. `safeCall` catches it; the loop continues for iterations N+1 … 20.
7. Each remaining iteration executes ~500 ms of EVM computation before the first DB query throws again (immediately caught).
8. Total wall-clock time: ~10 s (timeout) + (20 − N) × ~500 ms ≫ 10 s.
9. Repeat with many concurrent connections to exhaust the thread pool and DB connection pool.

**Expected result:** The server processes each `eth_estimateGas` request for significantly longer than `requestTimeout`, with no error returned to the caller until all 20 iterations complete.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L31-31)
```java
    private final long startTime = System.currentTimeMillis();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L99-101)
```java
    public void reset() {
        writeCache.clear();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-46)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L72-73)
```java
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
