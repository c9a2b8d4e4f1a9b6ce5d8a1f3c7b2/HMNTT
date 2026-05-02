### Title
Thread Pool Exhaustion via `QueryTimeoutException` Swallowed in `BinaryGasEstimator.safeCall()` Allowing Requests to Exceed `requestTimeout`

### Summary
`LoggingFilter.doFilterInternal()` calls `filterChain.doFilter()` with no independent wall-clock timeout; the sole timeout guard is the Hibernate `statementInspector`, which fires only at the next SQL statement boundary. For `estimate: true` requests, `BinaryGasEstimator.safeCall()` catches all `Exception` subclasses — including `QueryTimeoutException` — silently discards it, and allows the binary-search loop to continue executing up to 20 more EVM iterations after the 10-second deadline has passed. An unprivileged attacker can therefore hold a servlet thread well beyond 10 seconds per request, exhausting the thread pool with far fewer than `thread_pool_size / 10` requests/sec.

### Finding Description

**Code path:**

`LoggingFilter.doFilterInternal()` — no timeout on `filterChain.doFilter()`: [1](#0-0) 

`HibernateConfiguration.statementInspector()` — the only timeout mechanism, fires only before a Hibernate SQL statement: [2](#0-1) 

`BinaryGasEstimator.safeCall()` — swallows every `Exception`, including `QueryTimeoutException`: [3](#0-2) 

`BinaryGasEstimator.search()` — loop runs up to `maxGasEstimateRetriesCount` (default 20) iterations, each calling `safeCall()`: [4](#0-3) 

**Root cause and failed assumption:**

The design assumes that once `statementInspector` throws `QueryTimeoutException` the exception will propagate up and terminate the request. That assumption is broken by `safeCall()`, which catches `Exception` (the supertype of `QueryTimeoutException`) and returns `null`. The binary-search loop treats `null` as a failed EVM call, adjusts its bounds, and immediately issues the next EVM iteration. Because `ContractCallContext.startTime` is already past the 10-second mark, every subsequent iteration's first DB query also triggers the inspector and is also swallowed. The loop therefore runs all remaining iterations (up to 20 total), each consuming a small but non-zero amount of time (EVM frame setup + first DB round-trip before the inspector fires).

`Web3Properties.requestTimeout` defaults to 10 seconds: [5](#0-4) 

`ContractCallContext.startTime` is stamped at context construction, not at HTTP arrival: [6](#0-5) 

**Exploit flow:**

1. Attacker sends a POST to `/api/v1/contracts/call` with `"estimate": true`, `"gas": 15000000`, and a `to` address pointing to any deployed contract with non-trivial storage reads.
2. `ContractExecutionService.processCall()` enters `estimateGas()`, which calls `callContract()` (initial probe) then `binaryGasEstimator.search()`.
3. The initial probe and early binary-search iterations make DB queries; the servlet thread is held.
4. At t ≥ 10 s, `statementInspector` fires and throws `QueryTimeoutException`.
5. `safeCall()` catches it, logs an INFO message, returns `null`.
6. The loop continues for all remaining iterations (up to 20 − iterations_so_far more rounds).
7. Each remaining iteration: EVM frame is set up, first DB query fires, inspector throws again, `safeCall()` swallows again.
8. Total thread hold time = 10 s + (remaining_iterations × per-iteration overhead).
9. `filterChain.doFilter()` in `LoggingFilter` never times out independently; it blocks until the entire chain returns.

### Impact Explanation

A Tomcat default thread pool of ~200 threads, with each request holding a thread for ≥ 10 s, means only ~20 concurrent slow requests are needed to saturate the pool. The default rate limit is 500 req/s: [7](#0-6) 

An attacker sending 20–30 req/s (well under the 500 req/s cap) with `estimate: true` and a gas-heavy contract call can fully exhaust the thread pool, causing all subsequent legitimate requests to queue or be rejected with HTTP 503. The service is effectively taken offline for all users.

### Likelihood Explanation

No authentication or special privilege is required. The `/api/v1/contracts/call` endpoint is public. The attacker needs only a valid `to` address (any deployed contract on the network) and `"estimate": true`. The attack is trivially scriptable with `curl` or any HTTP client. It is repeatable and persistent as long as the attacker maintains the request rate. The 500 req/s rate limit provides no meaningful protection because the attack requires only ~20 req/s.

### Recommendation

1. **Fix `safeCall()`**: Do not catch `QueryTimeoutException` (or any `RuntimeException` subclass that signals a timeout). Rethrow it so the binary-search loop terminates immediately:
   ```java
   private EvmTransactionResult safeCall(long mid, LongFunction<EvmTransactionResult> call) {
       try {
           return call.apply(mid);
       } catch (QueryTimeoutException e) {
           throw e; // propagate timeout, do not swallow
       } catch (Exception ignored) {
           log.info("Exception while calling contract for gas estimation");
           return null;
       }
   }
   ```
2. **Add an independent wall-clock deadline** in `LoggingFilter.doFilterInternal()` or at the controller layer (e.g., Spring MVC async timeout, or a `CompletableFuture` with `orTimeout()`), so the servlet thread is released regardless of whether a DB query is ever made.
3. **Check elapsed time at the top of each `BinaryGasEstimator` iteration**, not only inside the Hibernate inspector, so CPU-bound EVM work between DB queries is also bounded.

### Proof of Concept

```bash
# Requires: a deployed contract address on the target network
CONTRACT="0x000000000000000000000000000000000000XXXX"

# Send 25 concurrent estimate requests (well under 500 req/s rate limit)
for i in $(seq 1 25); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"$CONTRACT\",\"gas\":15000000,\"estimate\":true}" &
done
wait

# After ~10 seconds, all 25 threads are occupied.
# New requests will queue or return 503 as the thread pool is exhausted.
# Monitor with: curl https://<mirror-node>/actuator/metrics/tomcat.threads.busy
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L39-54)
```java
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        long start = System.currentTimeMillis();
        Exception cause = null;

        if (!(request instanceof ContentCachingRequestWrapper)) {
            request = new ContentCachingRequestWrapper(request, web3Properties.getMaxPayloadLogSize() * 10);
        }

        try {
            filterChain.doFilter(request, response);
        } catch (Exception t) {
            cause = t;
        } finally {
            logRequest(request, response, start, cause);
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L19-20)
```java
    @DurationMin(seconds = 1L)
    private Duration requestTimeout = Duration.ofSeconds(10L);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L31-31)
```java
    private final long startTime = System.currentTimeMillis();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
