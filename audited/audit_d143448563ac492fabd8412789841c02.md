### Title
Gas Throttle Bypass via Integer Division Truncation in `scaleGas()`

### Summary
The `scaleGas()` method in `ThrottleProperties` uses integer floor division with a scale factor of 10,000, creating 10,000-unit bands where any gas value within a band costs the same number of tokens from `gasLimitBucket`. An unprivileged attacker can submit requests with `gas=29999` and consume only 2 tokens — identical to a `gas=21000` request — obtaining ~43% more gas throughput than the throttle design intends.

### Finding Description
**Code location:**
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java`, lines 42–47 (`scaleGas`)
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, line 40 (`throttle`)

**Root cause:**

```java
// ThrottleProperties.java:18,42-47
private static final long GAS_SCALE_FACTOR = 10_000L;

public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {
        return 0L;
    }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);  // integer truncation
}
```

`Math.floorDiv` truncates, so every gas value in the range `[N×10000, (N+1)×10000 − 1]` maps to the same token count `N`. Specifically:

| Gas value | `scaleGas()` result | Tokens consumed |
|-----------|---------------------|-----------------|
| 21,000    | `floor(21000/10000)` | **2** |
| 25,000    | `floor(25000/10000)` | **2** |
| 29,999    | `floor(29999/10000)` | **2** |
| 30,000    | `floor(30000/10000)` | **3** |

**Exploit flow:**

In `ThrottleManagerImpl.throttle()` (line 40):
```java
gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))
```
The bucket deducts `scaleGas(gas)` tokens. An attacker sets `gas=29999` in the `ContractCallRequest` JSON body. The `@Min(21_000)` constraint on `ContractCallRequest.gas` (line 37 of `ContractCallRequest.java`) is satisfied, so validation passes. The bucket deducts 2 tokens — the same as a `gas=21000` request — but the EVM is given 29,999 gas units to execute with.

**Why existing checks fail:**
- `@Min(21_000)` only enforces a lower bound; it does not prevent exploiting the truncation band.
- `validateContractMaxGasLimit` (ContractController line 92) only checks an upper ceiling, not intra-band abuse.
- There is no rounding-up or ceiling division in `scaleGas`.

### Impact Explanation
An attacker can consistently obtain `29999 / 21000 ≈ 1.428×` more EVM gas per throttle token than the design intends — a ~43% gas throughput surplus per request. At scale (e.g., 500 req/s rate limit), this translates to the attacker driving ~43% more EVM computation through the node than the operator configured, potentially exhausting node resources, degrading service for legitimate users, or enabling denial-of-service at lower cost than anticipated.

### Likelihood Explanation
No authentication or special privilege is required. Any external user can craft a JSON body with `"gas": 29999`. The attack is trivially repeatable, stateless, and requires no on-chain assets. It is exploitable by any party who can reach the `/api/v1/contracts/call` endpoint.

### Recommendation
Replace floor division with ceiling division in `scaleGas` so that the full gas value is always accounted for:

```java
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {
        return 1L; // charge at least 1 token for any valid request
    }
    // Ceiling division: (gas + GAS_SCALE_FACTOR - 1) / GAS_SCALE_FACTOR
    return Math.ceilDiv(gas, GAS_SCALE_FACTOR);
}
```

With ceiling division:
- `scaleGas(21000)` → 3
- `scaleGas(29999)` → 3
- `scaleGas(30000)` → 3
- `scaleGas(30001)` → 4

This ensures a higher gas value always costs at least as many tokens as a lower one, eliminating the free-gas band.

### Proof of Concept
**Precondition:** Access to the `/api/v1/contracts/call` HTTP endpoint (no authentication needed).

**Step 1 — Baseline (honest request):**
```bash
curl -X POST http://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":21000}'
# Consumes 2 tokens from gasLimitBucket
```

**Step 2 — Exploit (same token cost, ~43% more gas):**
```bash
curl -X POST http://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000001","gas":29999}'
# Also consumes only 2 tokens from gasLimitBucket
# EVM receives 29,999 gas instead of 21,000
```

**Step 3 — Repeat at rate limit:** Submit 500 requests/second (the `requestsPerSecond` default), each with `gas=29999`. The `gasLimitBucket` is drained at the same rate as if all requests used `gas=21000`, but the EVM processes ~43% more total gas per second than the operator's `gasPerSecond` configuration intends. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L36-37)
```java
    @Min(21_000)
    private long gas = 15_000_000L;
```
