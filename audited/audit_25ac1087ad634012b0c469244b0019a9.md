### Title
Gas Throttle Bypass via Minimum-Gas Requests: `scaleGas` Returns Near-Zero Tokens for `gas=21000`

### Summary
The `scaleGas` function in `ThrottleProperties` divides the request gas by `10_000`, meaning a request with `gas=21_000` (the `@Min` minimum enforced on `ContractCallRequest.gas`) consumes only **2 tokens** from the gas bucket per request. With a default gas bucket capacity of 750,000 tokens/second, an attacker sending minimum-gas requests exhausts only 0.13% of the gas bucket per second at the RPS ceiling, rendering the gas throttle completely ineffective as a computational-load defense for this class of requests.

### Finding Description

**Code path:**

`ContractCallRequest.gas` is annotated `@Min(21_000)`: [1](#0-0) 

In `ThrottleManagerImpl.throttle()`, the gas bucket is consumed via `throttleProperties.scaleGas(request.getGas())`: [2](#0-1) 

`scaleGas` is defined as: [3](#0-2) 

With `GAS_SCALE_FACTOR = 10_000` and `gas = 21_000`:
- `scaleGas(21_000)` = `Math.floorDiv(21_000, 10_000)` = **2 tokens** consumed per request.

The gas bucket is initialized with capacity `scaleGas(gasPerSecond)`: [4](#0-3) 

Default `gasPerSecond = 7_500_000_000L`: [5](#0-4) 

So `getGasPerSecond()` = `scaleGas(7_500_000_000)` = **750,000 tokens/second** bucket capacity.

**Root cause:** The `scaleGas` scaling factor of 10,000 was introduced to work around bucket4j's 1-token-per-nanosecond fill-rate ceiling, but it creates a massive asymmetry: the minimum allowed gas (21,000) maps to only 2 tokens, while the bucket holds 750,000 tokens/second. The gas throttle was designed to be the primary computational-load defense, but it is structurally inert for minimum-gas requests.

**Why existing checks fail:**

The `rateLimitBucket` (default 500 RPS) is the only binding constraint: [6](#0-5) 

At 500 RPS with gas=21,000: gas bucket consumption = 500 × 2 = 1,000 tokens/second out of 750,000 capacity (0.13%). The `gasLimitBucket.tryConsume()` check at line 40 **never returns false** for this workload. The gas throttle never fires.

The `gasLimitRefundPercent=100` restore path also does not help — `scaleGas(gasRemaining)` for small gas values rounds down to 0 or 1, so net consumption per request remains near zero: [7](#0-6) 

### Impact Explanation
The gas throttle's stated purpose is to cap total computational load (gas/second) processed by the node. With minimum-gas requests, this protection is entirely absent. An attacker can sustain the full 500 RPS indefinitely — each request still triggers a full EVM execution path through `contractExecutionService.processCall()` — without the gas throttle ever activating. If the operator raises `requestsPerSecond` (e.g., to 5,000 for higher-throughput deployments), the gas throttle remains the only intended backstop, and it still does not trigger for gas=21,000 requests (10,000 tokens/second vs. 750,000 capacity). This enables sustained EVM-execution DoS at the maximum permitted request rate with zero gas-bucket cost.

### Likelihood Explanation
No authentication, API key, or IP restriction is required. Any external user can POST to `/api/v1/contracts/call` with `{"gas": 21000, "to": "0x...", "data": "0x"}`. The attack is trivially scriptable with any HTTP client (curl, wrk, ab). The minimum gas value is publicly documented via the `@Min(21_000)` validation error message. The attack is fully repeatable and stateless.

### Recommendation
1. **Raise the effective minimum token cost**: Ensure `scaleGas(minGas)` ≥ some meaningful floor (e.g., ≥ 10 tokens). One approach: add a `Math.max(minimumTokenCost, Math.floorDiv(gas, GAS_SCALE_FACTOR))` guard in `scaleGas`, where `minimumTokenCost` is configurable.
2. **Alternatively, lower `GAS_SCALE_FACTOR`**: A factor of 1,000 instead of 10,000 would make `scaleGas(21_000)` = 21 tokens, still within bucket4j limits for the default `gasPerSecond`.
3. **Add per-IP rate limiting** as a complementary defense so a single client cannot consume the entire global RPS budget.

### Proof of Concept

```bash
# Flood /call with minimum-gas requests; gas throttle never triggers
for i in $(seq 1 500); do
  curl -s -o /dev/null -X POST https://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"gas":21000,"to":"0x00000000000000000000000000000000000004e2","data":"0x"}' &
done
wait
# All 500 requests succeed (HTTP 200 or EVM-level error, not 429).
# Gas bucket consumed: 500 * 2 = 1000 tokens out of 750,000 (0.13%).
# Repeat every second indefinitely — gas throttle never fires.
```

Expected: all requests pass the `gasLimitBucket.tryConsume(2)` check at `ThrottleManagerImpl.java:40` because 1,000 << 750,000. Only the `rateLimitBucket` (500 RPS) limits throughput, and it resets every second, so the attacker sustains maximum EVM load with zero gas-throttle resistance.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L36-37)
```java
    @Min(21_000)
    private long gas = 15_000_000L;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L24-26)
```java
    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L140-151)
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
```
