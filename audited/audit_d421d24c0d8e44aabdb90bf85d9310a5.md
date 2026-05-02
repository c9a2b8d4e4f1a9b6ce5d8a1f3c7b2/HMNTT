### Title
Rate-Limit Token Permanently Consumed on Gas-Check Failure Enables Unauthenticated DoS of `rateLimitBucket`

### Summary
In `ThrottleManagerImpl.throttle()`, a rate-limit token is consumed from `rateLimitBucket` before the gas check against `gasLimitBucket` is performed. When the gas check fails, a `ThrottleException` is thrown but the already-consumed rate-limit token is never restored. An unprivileged attacker can craft requests with a gas value that always exceeds the `gasLimitBucket`'s maximum capacity, rapidly draining all rate-limit tokens and denying service to legitimate users.

### Finding Description
**Exact code path:**

`ThrottleManagerImpl.throttle()` — `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 38–41:

```java
if (!rateLimitBucket.tryConsume(1)) {           // line 38 — token consumed here
    throw new ThrottleException(...);
} else if (!gasLimitBucket.tryConsume(          // line 40 — gas check second
        throttleProperties.scaleGas(request.getGas()))) {
    throw new ThrottleException(...);            // line 41 — rate token NOT restored
}
```

**Root cause:** The design assumes that any request passing the rate-limit check will also pass the gas check. There is no rollback of the rate-limit token when the gas check fails.

**`restore()` does not help:** `ThrottleManagerImpl.restore()` (lines 59–64) only adds tokens back to `gasLimitBucket`, never to `rateLimitBucket`. The controller's `catch (InvalidParametersException)` block (ContractController.java line 48) calls `throttleManager.restore(request.getGas())`, but this path is only reached for `InvalidParametersException`, not for `ThrottleException`. A gas-check failure throws `ThrottleException`, so `restore()` is never called.

**Bucket capacities (default config):**
- `rateLimitBucket`: capacity = `requestsPerSecond` = **500 tokens**, refills 500/second.
- `gasLimitBucket`: capacity = `scaleGas(7_500_000_000)` = `7_500_000_000 / 10_000` = **750,000 tokens**, refills 750,000/second.

**Exploit flow:**
1. Attacker sends a POST to `/api/v1/contracts/call` with `gas = 7_510_000_000` (no `@Max` constraint on `ContractCallRequest.gas`, only `@Min(21_000)`).
2. `scaleGas(7_510_000_000)` = `751_000`, which exceeds the `gasLimitBucket` maximum capacity of `750_000`.
3. `rateLimitBucket.tryConsume(1)` succeeds → 1 token consumed.
4. `gasLimitBucket.tryConsume(751_000)` fails (exceeds max capacity, will **always** fail regardless of bucket state) → `ThrottleException` thrown.
5. Rate-limit token is permanently lost.
6. Attacker repeats 500 times within 1 second → `rateLimitBucket` fully depleted.
7. All subsequent legitimate requests receive `"Requests per second rate limit exceeded"` for the remainder of that second.
8. Attacker repeats every second to sustain the DoS.

**`validateContractMaxGasLimit` is bypassed:** This check (ContractController.java line 41–43) runs *after* `throttleManager.throttle(request)` (line 40), so it cannot prevent the rate-limit token from being consumed.

### Impact Explanation
Any unauthenticated user can continuously deny service to all legitimate callers of the `/api/v1/contracts/call` endpoint. With default settings (500 req/s limit), the attacker needs only 500 HTTP requests per second — trivially achievable — to keep the `rateLimitBucket` at zero indefinitely. Legitimate users receive HTTP 429 errors for all contract call and estimate requests. The `gasLimitBucket` is unaffected, meaning the attacker wastes no gas budget while executing the attack.

### Likelihood Explanation
The attack requires no authentication, no special privileges, and no knowledge of deployed contracts. The only requirement is the ability to send HTTP POST requests with a crafted `gas` field. The gas value needed (`> 7_500_000_000` with defaults) is a valid `long` that passes Bean Validation. The attack is fully repeatable, automatable with a simple script, and sustainable indefinitely. Likelihood is **high**.

### Recommendation
1. **Atomic check-or-rollback:** Restore the rate-limit token when the gas check fails. Add `rateLimitBucket.addTokens(1)` before throwing in the gas-check branch, or restructure to check gas first and rate-limit second.
2. **Validate gas before throttle:** Move `validateContractMaxGasLimit` (or an equivalent `@Max` Bean Validation constraint on `ContractCallRequest.gas`) to execute before `throttleManager.throttle()` is called, so oversized gas values are rejected before any bucket tokens are consumed.
3. **Extend `restore()` interface:** Add a `restoreRateLimit()` method or a combined atomic `throttle()` that rolls back all consumed tokens on any internal failure.

### Proof of Concept
```bash
# Default gasLimitBucket max capacity = 750,000 scaled tokens
# gas = 7,510,000,000 → scaleGas = 751,000 > 750,000 → always fails gas check

for i in $(seq 1 500); do
  curl -s -o /dev/null -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d '{"gas": 7510000000, "to": "0x0000000000000000000000000000000000000001", "data": "0x"}' &
done
wait

# Now send a legitimate request — it will be rejected:
curl -X POST http://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"gas": 50000, "to": "0x<valid_contract>", "data": "0x"}'
# Response: 429 "Requests per second rate limit exceeded"
```

Repeat the loop every second to sustain the denial of service. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-50)
```java
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L36-37)
```java
    @Min(21_000)
    private long gas = 15_000_000L;
```
