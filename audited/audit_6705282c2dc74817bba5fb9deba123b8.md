### Title
Gas Token Leak via Unrestored Tokens When `action()` Throws `ThrottleException` After `gasLimitBucket` Consumption

### Summary
In `ThrottleManagerImpl.throttle()`, gas tokens are consumed from `gasLimitBucket` before per-request filter actions are evaluated. If a configured `REJECT` or exhausted `THROTTLE` filter subsequently throws a `ThrottleException`, `ContractController.call()` does not catch it and never calls `restore()`, permanently losing those gas tokens. An unprivileged attacker who can craft requests matching a `REJECT` filter can repeatedly drain the shared gas budget, starving legitimate users.

### Finding Description
**Code path:**

`ContractController.call()` (lines 38–51) wraps `throttleManager.throttle(request)` in a try-block that catches only `InvalidParametersException` and calls `restore()` for that case:

```java
// ContractController.java lines 39-50
try {
    throttleManager.throttle(request);          // gas tokens consumed here
    validateContractMaxGasLimit(request);
    ...
} catch (InvalidParametersException e) {
    throttleManager.restore(request.getGas()); // only restores for this exception
    throw e;
}
// ThrottleException is NOT caught → restore() is never called
```

Inside `ThrottleManagerImpl.throttle()` (lines 37–49), the ordering is:

1. **Line 38–39**: `rateLimitBucket.tryConsume(1)` — if false, throws before any gas is consumed. Safe.
2. **Line 40–42**: `gasLimitBucket.tryConsume(scaleGas(request.getGas()))` — if **true**, gas tokens are **permanently consumed**.
3. **Lines 44–48**: Iterates `requestFilter` list and calls `action()`.

`action()` (lines 66–76) throws `ThrottleException` unconditionally for `REJECT`, and for `THROTTLE` when the per-filter bucket is exhausted:

```java
case REJECT -> throw new ThrottleException("Invalid request");   // always throws on match
case THROTTLE -> {
    if (!filter.getBucket().tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

When either branch throws, execution unwinds through `throttle()` back to `call()`. Because `ThrottleException` is not caught there, `restore()` is never invoked, and the gas tokens consumed at step 2 are permanently lost.

**Root cause**: The failed assumption is that a `ThrottleException` from `action()` means "no work was done, no resources were consumed." In reality, gas tokens were already consumed at line 40 before the filter loop runs.

### Impact Explanation
The `gasLimitBucket` is a shared, global resource governing how much gas all users can consume per second (default 7.5 B gas/s, scaled by 10,000 = 750,000 tokens/s). Each leaked request with gas = 15,000,000 (max) drains 1,500 tokens. At the 500 req/s rate limit, a single attacker can drain the entire gas budget (750,000 tokens/s) without any actual EVM execution occurring. Legitimate users then receive `"Gas per second rate limit exceeded"` errors, effectively a complete DoS of the `/api/v1/contracts/call` endpoint. Mirror node record export for those blocked calls never happens.

### Likelihood Explanation
Exploitability requires a `REJECT` or `THROTTLE` filter to be configured in `hiero.mirror.web3.throttle.request`. The default is an empty list (`List.of()`), so default deployments are not affected. However, operators commonly configure `REJECT` filters to block known-bad contract addresses or calldata patterns. Any attacker who can observe or guess those patterns (e.g., a blocked contract address is public on-chain) can immediately exploit this with no credentials, no special role, and no prior state — just repeated HTTP POST requests to a public endpoint.

### Recommendation
Add a `catch (ThrottleException e)` block in `ContractController.call()` that calls `restore()` **only when gas was already consumed** (i.e., the exception originated from `action()`, not from the initial `gasLimitBucket` check). The cleanest fix is to restructure `throttle()` so that gas tokens are consumed **after** all filter actions pass, or to have `action()` signal rejection without consuming gas first. Alternatively, catch `ThrottleException` in `call()` and always call `restore()`:

```java
} catch (ThrottleException e) {
    throttleManager.restore(request.getGas());
    throw e;
}
```

This is safe because `restore()` is a no-op when `scaleGas(gas) == 0`, and over-restoring is bounded by the bucket's capacity.

### Proof of Concept
1. Configure a `REJECT` filter matching requests to a specific contract address `0xDEAD...`:
   ```yaml
   hiero.mirror.web3.throttle.request:
     - action: REJECT
       filters:
         - to: "0xDEAD..."
   ```
2. Send 500 POST requests/second to `/api/v1/contracts/call` with `"to": "0xDEAD..."` and `"gas": 15000000`.
3. Each request: `rateLimitBucket` consumes 1 token, `gasLimitBucket` consumes 1500 tokens, `action()` throws `ThrottleException("Invalid request")`, `restore()` is never called.
4. After ~1 second, `gasLimitBucket` is exhausted (750,000 tokens drained).
5. All subsequent legitimate requests (any `to` address) receive `"Gas per second rate limit exceeded"` until the bucket refills.
6. Repeat indefinitely to maintain the DoS.