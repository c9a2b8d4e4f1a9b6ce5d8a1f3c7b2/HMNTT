### Title
Gas Throttle Fully Bypassed for Failing Transactions Due to Default 100% Refund, Enabling Sustained Maximum EVM Load

### Summary
The `gasLimitBucket` in `ThrottleConfiguration.java` is designed to cap total gas consumed per second, but `restoreGasToBucket()` in `ContractCallService.java` restores the **full gasLimit** back to the bucket when a transaction fails with `gasUsed == gasLimit`, because `gasLimitRefundPercent` defaults to `100`. This makes the gas throttle a no-op for failing transactions: an attacker can cycle consume→execute(fail)→restore indefinitely, sustaining maximum EVM execution load bounded only by the rate-limit bucket (500 req/sec), which is shared with legitimate users.

### Finding Description

**Root cause — default `gasLimitRefundPercent = 100`:**

`ThrottleProperties.java` line 22:
```java
private float gasLimitRefundPercent = 100;
``` [1](#0-0) 

**Restore formula in `restoreGasToBucket()`:**

```java
final var gasLimitToRestoreBaseline = (long) (gasLimit * throttleProperties.getGasLimitRefundPercent() / 100f);
if (result == null || (!result.isSuccessful() && gasLimit == result.gasUsed())) {
    throttleManager.restore(gasLimitToRestoreBaseline);
``` [2](#0-1) 

With `gasLimitRefundPercent = 100`, `gasLimitToRestoreBaseline = gasLimit * 100 / 100 = gasLimit`. The full gasLimit is unconditionally restored when `gasUsed == gasLimit`.

**`restore()` calls `addTokens()` directly:**

```java
public void restore(long gas) {
    long tokens = throttleProperties.scaleGas(gas);
    if (tokens > 0) {
        gasLimitBucket.addTokens(tokens);
    }
}
``` [3](#0-2) 

**Exploit cycle:**
1. Attacker sends `eth_call` with `gas = G` (e.g., 15,000,000). `gasLimitBucket.tryConsume(scaleGas(G))` succeeds, consuming tokens.
2. EVM executes the call fully (CPU/memory consumed).
3. Call fails with `gasUsed == gasLimit` (trivially achieved by targeting a contract that exhausts gas, or by setting gas just below what the call needs).
4. `restoreGasToBucket` restores `scaleGas(G)` tokens — net bucket change = 0.
5. Attacker immediately repeats from step 1.

**Why existing checks fail:**

- `gasLimitBucket` check at `ThrottleManagerImpl.java` line 40 fires *before* execution. After execution the tokens are fully returned, so the bucket never depletes across sequential failing requests. [4](#0-3) 
- `rateLimitBucket` (500 req/sec) is the only remaining guard, but it is a global shared limit — consuming it starves legitimate users simultaneously. [5](#0-4) 
- `bucket4j`'s `addTokens` caps at bucket capacity, so the bucket cannot be inflated above its maximum, but this does not prevent the cycle — it only prevents over-inflation.

### Impact Explanation
The gas throttle's entire purpose is to bound EVM CPU/memory consumption per second. With the default configuration, it provides zero protection against an attacker sending sequential failing transactions. The attacker can drive the node to execute EVM at the maximum rate permitted by the rate-limit bucket (500 req/sec × up to 15M gas each), sustaining near-maximum EVM load indefinitely. This can increase node resource consumption well beyond 30% compared to baseline, and simultaneously degrades service for legitimate users by consuming the shared rate-limit budget.

### Likelihood Explanation
No privileges, no account, and no on-chain funds are required — `eth_call` is a read-only, unauthenticated JSON-RPC endpoint. Crafting a call that exhausts gas is trivial (call a non-existent function on a contract, or any infinite-loop contract). The attack is fully repeatable and scriptable with a simple HTTP client loop. The default `gasLimitRefundPercent = 100` means every out-of-the-box deployment is affected unless an operator has explicitly lowered this value.

### Recommendation
1. **Lower the default `gasLimitRefundPercent`** to a value significantly below 100 (e.g., 10–25%). This ensures that even when a transaction fails with `gasUsed == gasLimit`, only a fraction of the consumed gas is returned, so the bucket depletes under sustained attack. [6](#0-5) 
2. **Add per-IP or per-caller rate limiting** so a single attacker cannot consume the entire global rate-limit budget.
3. **Document the security implication** of `gasLimitRefundPercent = 100` so operators understand that the gas throttle is effectively disabled for failing calls at that setting.

### Proof of Concept
```
# Prerequisites: mirror-node web3 running with default config (gasLimitRefundPercent=100)
# Target: any contract address that will exhaust gas (e.g., infinite loop, or just use a
#         gas limit slightly below what a complex call needs)

while true; do
  curl -s -X POST http://<mirror-node>:8545 \
    -H 'Content-Type: application/json' \
    -d '{
      "jsonrpc":"2.0","method":"eth_call",
      "params":[{
        "to":"<complex-contract-address>",
        "data":"<calldata-for-expensive-function>",
        "gas":"0xE4E1C0"
      },"latest"],
      "id":1
    }'
done
```
Each iteration: (1) consumes `scaleGas(15_000_000)` tokens from `gasLimitBucket`; (2) EVM executes fully; (3) call fails with `gasUsed == gasLimit`; (4) full tokens restored via `addTokens`; (5) loop repeats. Node CPU climbs continuously. The `rateLimitBucket` (500 req/sec) is the only brake, and it is shared — legitimate traffic is crowded out simultaneously.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L20-23)
```java
    @Min(0)
    @Max(100)
    private float gasLimitRefundPercent = 100;

```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L143-145)
```java
        final var gasLimitToRestoreBaseline = (long) (gasLimit * throttleProperties.getGasLimitRefundPercent() / 100f);
        if (result == null || (!result.isSuccessful() && gasLimit == result.gasUsed())) {
            throttleManager.restore(gasLimitToRestoreBaseline);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L38-39)
```java
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L40-41)
```java
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L59-64)
```java
    public void restore(long gas) {
        long tokens = throttleProperties.scaleGas(gas);
        if (tokens > 0) {
            gasLimitBucket.addTokens(tokens);
        }
    }
```
