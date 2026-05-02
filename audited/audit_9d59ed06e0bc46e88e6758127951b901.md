Now I have all the data needed. Let me verify the exact math from the code before writing the finding.

**Verified facts:**
- `gasPerSecond` default = `7_500_000_000L` [1](#0-0) 
- `GAS_SCALE_FACTOR` = `10_000L` → `getGasPerSecond()` = `750_000` tokens (bucket capacity) [2](#0-1) 
- Bucket capacity = `gasPerSecond` (no burst headroom) [3](#0-2) 
- `requestsPerSecond` default = `500` [4](#0-3) 
- Default and max `gas` per request = `15_000_000L` [5](#0-4) 
- `maxGasLimit` = `15_000_000L` [6](#0-5) 
- `scaleGas(15_000_000)` = `floor(15_000_000 / 10_000)` = `1_500` tokens/request
- `500 requests × 1_500 tokens = 750_000 tokens` = full bucket capacity

The math is exact. All validation gates pass.

---

### Title
Gas Bucket Exhaustion DoS via Maximum-Gas Requests at Full RPS Rate

### Summary
The `gasLimitBucket` capacity is set equal to `gasPerSecond` (750,000 scaled tokens by default), and the per-request token cost at the maximum allowed gas (`15,000,000`) is exactly `1,500` tokens. Because the RPS rate limit is `500`, a single unauthenticated attacker can send exactly 500 requests per second at `gas=15,000,000` to consume all 750,000 tokens in one second, starving every other user of gas budget for the entire refill window. No credentials or special access are required.

### Finding Description
**Code path:**

- `ContractController.call()` (line 40) calls `throttleManager.throttle(request)` before any authentication or per-user check.
- `ThrottleManagerImpl.throttle()` (lines 38–42) first deducts 1 token from `rateLimitBucket`, then deducts `scaleGas(request.getGas())` tokens from `gasLimitBucket`. If either deduction fails, a `ThrottleException` is thrown immediately.
- `ThrottleConfiguration.gasLimitBucket()` (lines 35–45) builds the bucket with `capacity = getGasPerSecond()` and a greedy refill of the same amount per second — meaning the bucket starts full at 750,000 tokens and refills to exactly 750,000 tokens every second.
- `ThrottleProperties.scaleGas(15_000_000)` = `floor(15_000_000 / 10_000)` = **1,500 tokens**.
- `ThrottleProperties.requestsPerSecond` = **500**.

**Root cause / failed assumption:**

The designers assumed that no single client would be able to send enough requests at maximum gas to exhaust the bucket. However, `500 RPS × 1,500 tokens/request = 750,000 tokens = bucket capacity`. The two limits are perfectly aligned, so the rate limiter provides zero protection against a single attacker who uses the full RPS allowance at maximum gas.

**Exploit flow:**

1. Attacker sends 500 POST `/api/v1/contracts/call` requests per second, each with `gas=15000000` (the default value, within `maxGasLimit`).
2. Each request passes the `rateLimitBucket` check (500 tokens available) and deducts 1,500 tokens from `gasLimitBucket`.
3. After 500 requests, `gasLimitBucket` is at 0.
4. Any subsequent request from any user (including legitimate ones) fails with `"Gas per second rate limit exceeded"` until the bucket refills after 1 second.
5. The attacker immediately repeats, keeping the bucket perpetually empty.

**Why existing checks are insufficient:**

- The `rateLimitBucket` (500 RPS) does not prevent this — the attacker stays within it.
- `validateContractMaxGasLimit` (line 93) only rejects gas > 15,000,000; `gas=15,000,000` is the default and is accepted.
- `gasLimitRefundPercent=100` restores gas after execution, but the restore happens asynchronously after processing, while the throttle check is synchronous and upfront. The attacker's next wave of requests arrives before restores complete.
- There is no per-IP, per-user, or per-source rate limiting anywhere in the throttle path.

### Impact Explanation
All users of the mirror node's web3 API (`/api/v1/contracts/call`) are denied service for as long as the attacker sustains the attack. Every request returns a throttle error. The attack is sustainable indefinitely at 500 RPS, which is a trivially low request rate achievable from a single machine. While this does not affect the Hedera consensus network directly, it renders the mirror node's EVM simulation endpoint completely unavailable, blocking dApps, tooling, and integrations that depend on `eth_call` / `eth_estimateGas` via this node.

### Likelihood Explanation
The attack requires no authentication, no special knowledge beyond the public API, and no elevated privileges. The attacker only needs to send HTTP POST requests at 500 RPS with `gas=15000000` — a value that is the documented default. Any developer or script with basic HTTP tooling (e.g., `wrk`, `ab`, `hey`) can reproduce this. The attack is repeatable, stateless, and requires no coordination. Likelihood is high.

### Recommendation
1. **Decouple bucket capacity from refill rate**: Set `capacity` to a multiple of `gasPerSecond` (e.g., 5×) so a single second of maximum-rate traffic cannot drain the entire bucket.
2. **Add per-source rate limiting**: Introduce per-IP or per-authenticated-client gas and RPS sub-buckets so one client cannot monopolize the global budget.
3. **Reduce `maxGasLimit` relative to `gasPerSecond`**: Ensure `requestsPerSecond × scaleGas(maxGasLimit) < capacity` by a meaningful margin (e.g., ≤ 50% of capacity per second from a single source).
4. **Enforce a lower default gas**: The default `gas=15_000_000` in `ContractCallRequest` is the maximum; consider defaulting to a lower value and requiring callers to explicitly opt into high gas.

### Proof of Concept
```bash
# Requires: wrk or any HTTP load tool capable of 500 RPS
# Target: mirror node web3 endpoint

cat > payload.json <<'EOF'
{
  "data": "0x",
  "to": "0x0000000000000000000000000000000000000167",
  "gas": 15000000
}
EOF

# Send 500 req/s for 5 seconds from a single client
wrk -t10 -c500 -d5s \
    -s <(echo 'wrk.method="POST"; wrk.body=io.open("payload.json"):read("*a"); wrk.headers["Content-Type"]="application/json"') \
    http://<mirror-node-host>/api/v1/contracts/call

# Expected result after ~1 second:
# All responses return HTTP 429 with body:
# {"_status":{"messages":[{"message":"Gas per second rate limit exceeded."}]}}
# for ALL clients, including legitimate ones, until the bucket refills.
```

**Reproduction steps:**
1. Stand up the mirror node with default configuration.
2. Fire 500 concurrent POST requests to `/api/v1/contracts/call` with `gas=15000000` within 1 second.
3. Immediately after, send a single legitimate request from a different client.
4. Observe the legitimate request is rejected with the gas throttle error despite the attacker staying within the documented RPS limit.

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L35-45)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L36-37)
```java
    @Min(21_000)
    private long gas = 15_000_000L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L64-65)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;
```
