### Title
Predictable `refillGreedy` Cycle Enables Single-User Global Gas Budget Monopolization (Griefing DoS)

### Summary
The `gasLimitBucket` in `ThrottleManagerImpl` uses a globally shared Bucket4j bucket configured with `refillGreedy(gasLimit, Duration.ofSeconds(1))`. Because there are no per-user or per-IP gas limits, a single unprivileged caller can submit one request consuming the entire gas budget, then time subsequent bursts to the perfectly predictable 1-second refill boundary, continuously starving all other users of gas capacity across every window.

### Finding Description
**Code locations**:
- `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java` lines 34–45: `gasLimitBucket` is a single JVM-global bucket with `refillGreedy(gasLimit, Duration.ofSeconds(1))`.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java` lines 37–48: `throttle()` deducts `scaleGas(request.getGas())` tokens from this shared bucket with no per-caller accounting.
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java` lines 42–47: `scaleGas()` divides by `GAS_SCALE_FACTOR = 10_000`, so the default `gasPerSecond = 7_500_000_000` becomes 750,000 scaled tokens — the entire bucket capacity.

**Root cause**: `refillGreedy` in Bucket4j refills tokens continuously and proportionally to elapsed time. After the bucket is drained at time T, it is guaranteed to be full again at exactly T + 1 s. This is deterministic and observable by any caller (a rejected request signals exhaustion; the next accepted request signals refill). Combined with the absence of any per-user gas accounting, a single caller can:

1. Submit one request with `gas = gasPerSecond` (7.5 B gas, the maximum allowed by `@Max(10_000_000_000_000L)`), consuming all 750,000 scaled tokens.
2. Observe the `ThrottleException("Gas per second rate limit exceeded.")` on subsequent requests to detect the exact drain moment.
3. Poll with a lightweight request every ~1 s to detect the refill, then immediately submit the next max-gas request.
4. Repeat indefinitely.

**Why existing checks fail**:
- `rateLimitBucket` (default 500 req/s) only limits request count, not gas per caller. One request per second is well within this limit.
- `restore()` / `restoreGasToBucket()` in `ContractCallService` (lines 140–152) returns only *unused* gas. If the attacker's transaction actually executes and consumes gas, nothing is restored. Even if some gas is returned, the attacker can absorb it into their next burst.
- There is no IP-level, account-level, or session-level gas quota anywhere in the throttle stack.

### Impact Explanation
Every legitimate user sharing the same mirror-node instance is denied gas capacity for up to ~1 second per cycle. Because the attack requires only 1 request per second (far below the 500 req/s rate limit), it can be sustained indefinitely at negligible cost to the attacker. All `eth_call` / `eth_estimateGas` requests from other users receive `ThrottleException` with `"Gas per second rate limit exceeded."` for the duration of each exhaustion window. This is a sustained, repeatable griefing DoS with no economic barrier.

### Likelihood Explanation
The attack requires zero privileges — only HTTP access to the web3 endpoint. The refill timing is deterministic and self-revealing (the attacker learns the drain moment from the error response and the refill moment from the first successful response). No special tooling is needed; a simple script sending one max-gas request per second suffices. The attack is repeatable across any number of windows without interruption.

### Recommendation
1. **Add per-caller gas limits**: Track gas consumption per IP address (or authenticated identity) using a separate per-caller bucket or a sliding-window counter, and reject requests that exceed a per-caller share of the global budget.
2. **Cap the gas a single request may claim**: Enforce a per-request gas ceiling (e.g., 10–20% of `gasPerSecond`) so no single request can drain the entire bucket.
3. **Consider `refillIntervally` or a token-bucket with initial tokens = 0**: `refillIntervally` adds tokens at fixed wall-clock intervals, which does not change the fundamental issue but removes the continuous-accumulation property that makes partial-window timing trivial. The real fix is (1) and (2).
4. **Rate-limit by gas per caller per second** at the API gateway or load-balancer layer as a defense-in-depth measure.

### Proof of Concept
```
# Pseudocode — no privileges required
GAS_MAX = 7_500_000_000   # gasPerSecond default

while True:
    resp = eth_call(gas=GAS_MAX, ...)   # drains entire bucket
    assert resp.ok                       # first call in window succeeds

    # Spin until refill detected (≈1 s)
    while True:
        probe = eth_call(gas=GAS_MAX, ...)
        if probe.ok:
            break   # bucket just refilled; immediately consumed again
        # probe returns ThrottleException("Gas per second rate limit exceeded.")
        sleep(0.001)

# Result: all other callers receive ThrottleException for every window
```

Reproducible steps:
1. Deploy the mirror-node web3 module with default `ThrottleProperties`.
2. From a single client, send `POST /api/v1/contracts/call` with `"gas": 7500000000` in a tight loop.
3. Observe that a second concurrent client receives `"Gas per second rate limit exceeded."` on every request for the duration of the test. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-48)
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L140-152)
```java
    private void restoreGasToBucket(EvmTransactionResult result, long gasLimit) {
        // If the transaction fails, gasUsed is equal to gasLimit, so restore the configured refund percent
        // of the gasLimit value back in the bucket.
        final var gasLimitToRestoreBaseline = (long) (gasLimit * throttleProperties.getGasLimitRefundPercent() / 100f);
        if (result == null || (!result.isSuccessful() && gasLimit == result.gasUsed())) {
            throttleManager.restore(gasLimitToRestoreBaseline);
        } else {
            // The transaction was successful or reverted, so restore the remaining gas back in the bucket or
            // the configured refund percent of the gasLimit value back in the bucket - whichever is lower.
            final var gasRemaining = gasLimit - result.gasUsed();
            throttleManager.restore(Math.min(gasRemaining, gasLimitToRestoreBaseline));
        }
    }
```
