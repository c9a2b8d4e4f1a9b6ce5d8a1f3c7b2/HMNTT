### Title
Gas Throttle Bypass via Integer Truncation in `scaleGas()` — Up to ~2x Intended Gas Per Token

### Summary
The `scaleGas()` method in `ThrottleProperties.java` uses `Math.floorDiv(gas, 10_000)` to convert raw gas values into bucket tokens. Because integer division discards the remainder, any gas value in the range `(n×10,000, (n+1)×10,000 − 1]` costs exactly `n` tokens regardless of how close it is to the upper boundary. An unprivileged attacker can exploit this by always submitting gas values of `19,999`, consuming 1 token while representing nearly 2× the gas of the minimum 1-token transaction (`10,001`), effectively doubling the gas throughput allowed through the throttle.

### Finding Description

**Exact code path:**

`ThrottleProperties.scaleGas()` — [1](#0-0) 

```java
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {   // GAS_SCALE_FACTOR = 10_000
        return 0L;
    }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);
}
```

This result is used directly in `ThrottleManagerImpl.throttle()` to consume tokens from `gasLimitBucket`: [2](#0-1) 

**Root cause:** `Math.floorDiv` silently discards up to `9,999` gas units of remainder per call. The failed assumption is that each token represents a fixed, bounded amount of gas. In reality, one token can represent anywhere from `10,001` to `19,999` gas (for the 1-token case), a ratio of nearly 2:1.

**Exploit flow:**
- Attacker submits repeated requests with `gas = 19,999`.
- `scaleGas(19_999)` → `Math.floorDiv(19_999, 10_000)` = **1 token consumed**.
- A legitimate user submitting `gas = 10,001` also consumes **1 token**.
- The attacker therefore gets ~99.98% more gas execution per token than the minimum 1-token transaction.
- The same truncation applies in `restore()` (line 60–63), so refunds are also under-credited, compounding the imbalance. [3](#0-2) 

**Why existing checks are insufficient:**
The only guard in `scaleGas()` is `gas <= GAS_SCALE_FACTOR → return 0L`, which addresses a separate edge case (zero-cost transactions). There is no rounding, ceiling division, or minimum-token enforcement that would close the truncation gap. [4](#0-3) 

### Impact Explanation

The default `gasPerSecond` is `7,500,000,000`, which scales to `750,000` tokens/second in the bucket. [5](#0-4) 

- **Intended limit:** `750,000 tokens/s × 10,000 gas/token = 7,500,000,000 gas/s`
- **Attacker achieves:** `750,000 tokens/s × 19,999 gas/token ≈ 14,999,250,000 gas/s`

The gas-per-second DoS protection is effectively halved. An attacker can drive ~2× the intended computational load through the node before being throttled, degrading service for all other users.

### Likelihood Explanation

- **No privileges required.** Any caller of `eth_call` or `eth_estimateGas` can set an arbitrary `gas` field in the JSON-RPC request.
- **Trivially repeatable.** The attacker simply always sets `gas: 19999` (or any value `n×10000 − 1`) in every request.
- **No on-chain cost.** These are simulation/read calls; there is no financial deterrent.
- **Automatable.** A script sending requests in a tight loop at the rate limit is sufficient.

### Recommendation

Replace floor division with ceiling division so that every gas unit is accounted for by at least one token:

```java
public long scaleGas(long gas) {
    if (gas <= 0) {
        return 0L;
    }
    // Ceiling division: ensures no gas goes unaccounted
    return Math.ceilDiv(gas, GAS_SCALE_FACTOR); // Java 18+
    // Or equivalently: (gas + GAS_SCALE_FACTOR - 1) / GAS_SCALE_FACTOR
}
```

This ensures `scaleGas(19_999)` = **2 tokens**, not 1, eliminating the truncation gap. Also review the `gas <= GAS_SCALE_FACTOR → 0L` branch: under ceiling division, any gas > 0 will cost at least 1 token, so that special case can be removed or adjusted. [1](#0-0) 

### Proof of Concept

**Precondition:** Mirror node running with default config (`gasPerSecond = 7_500_000_000`).

**Steps:**

1. Send a burst of JSON-RPC requests with `gas: 19999`:
   ```bash
   for i in $(seq 1 750000); do
     curl -s -X POST http://localhost:8545 \
       -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x...","gas":"0x4E1F"},"latest"],"id":1}' &
   done
   ```
   (`0x4E1F` = 19,999 decimal)

2. Each request consumes exactly **1 token** from `gasLimitBucket` (same as a `gas: 10001` request).

3. All 750,000 requests are accepted within 1 second, representing **~14,999,250,000 gas** of execution — nearly **2× the intended 7,500,000,000 gas/s limit**.

4. Repeat with `gas: 10001` to confirm it also consumes 1 token, demonstrating the 2:1 gas-per-token disparity.

**Expected (correct) behavior:** `gas: 19999` should consume **2 tokens**, limiting the burst to `750,000 / 2 = 375,000` such requests per second, keeping total gas within the intended budget.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L26-26)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L40-42)
```java
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L59-63)
```java
    public void restore(long gas) {
        long tokens = throttleProperties.scaleGas(gas);
        if (tokens > 0) {
            gasLimitBucket.addTokens(tokens);
        }
```
