### Title
Gas Throttle Bypass via Zero-Scaled Gas: `scaleGas()` Returns 0 for `gas ≤ 10,000`, Allowing `gasLimitBucket` to Be Consumed for Free

### Summary
`ThrottleProperties.scaleGas()` returns `0L` for any `gas` value at or below `GAS_SCALE_FACTOR` (10,000). In `ThrottleManagerImpl.throttle()`, this 0 is passed directly to `gasLimitBucket.tryConsume(0)`, which always returns `true` in bucket4j (consuming zero tokens trivially succeeds). As a result, the gas-per-second throttle is completely bypassed for every request carrying `gas ≤ 10,000`, and the only remaining guard is the `rateLimitBucket` (default 500 req/s).

### Finding Description

**Exact code path:**

`ThrottleProperties.scaleGas()` — [1](#0-0) 

```java
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {   // GAS_SCALE_FACTOR = 10_000
        return 0L;                   // ← returns 0 for any gas ≤ 10,000
    }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);
}
```

`ThrottleManagerImpl.throttle()` — [2](#0-1) 

```java
public void throttle(ContractCallRequest request) {
    if (!rateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
        // ↑ when gas ≤ 10,000, scaleGas() = 0 → tryConsume(0) always returns true
        throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
    }
```

**Root cause:** There is no guard against a zero-token consumption before calling `gasLimitBucket.tryConsume(...)`. In bucket4j, `tryConsume(0)` always returns `true` because consuming zero tokens is trivially satisfied regardless of bucket state. The `gasLimitBucket` is never decremented.

**Asymmetry with `restore()`:** The developer correctly guarded against this in `restore()` — [3](#0-2)  — with `if (tokens > 0)` before calling `addTokens`, but omitted the equivalent guard in `throttle()`.

**Exploit flow:**
1. Attacker sends `eth_call` / `eth_estimateGas` requests with `gas=1` (or any value 1–10,000).
2. `scaleGas(1)` → `0`.
3. `gasLimitBucket.tryConsume(0)` → `true` (no tokens consumed).
4. Only `rateLimitBucket.tryConsume(1)` is enforced (default capacity: 500/s).
5. The `gasLimitBucket` remains perpetually full; legitimate high-gas requests are never throttled by gas either, but the attacker's requests consume zero gas budget indefinitely.

### Impact Explanation
The gas-per-second throttle — the primary defense against computational overload — is rendered completely inoperative for any request with `gas ≤ 10,000`. An attacker can sustain 500 requests/second (the rate-limit ceiling) with `gas=9,999` each, bypassing all gas accounting. The `gasLimitBucket` is never depleted, so it provides no protection. The intended two-layer defense (rate + gas) collapses to a single layer. [4](#0-3) 

### Likelihood Explanation
No authentication or special privilege is required. Any external caller can set `gas` to an arbitrary value in a JSON-RPC request. The condition (`gas ≤ 10,000`) is trivially satisfied and requires no knowledge of internals. The attack is fully repeatable and automatable. [5](#0-4) 

### Recommendation
Add the same zero-guard that exists in `restore()` to `throttle()`. Treat any scaled gas of 0 as a minimum of 1 token, or reject requests whose scaled gas is 0:

```java
long scaledGas = throttleProperties.scaleGas(request.getGas());
long tokensToConsume = Math.max(1L, scaledGas);   // enforce minimum of 1
if (!gasLimitBucket.tryConsume(tokensToConsume)) {
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
```

Alternatively, validate at the request layer that `gas` must be `> GAS_SCALE_FACTOR` (10,000) before reaching the throttle. [1](#0-0) 

### Proof of Concept
```bash
# Send 500 requests/second with gas=1 — gasLimitBucket is never touched
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"0x","gas":1,"to":"0x0000000000000000000000000000000000000001"}' &
done
wait

# Observe: all 500 requests succeed (rate limit allows it),
# gasLimitBucket token count remains at full capacity (never decremented),
# gas throttle provides zero protection.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L18-18)
```java
    private static final long GAS_SCALE_FACTOR = 10_000L;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
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
