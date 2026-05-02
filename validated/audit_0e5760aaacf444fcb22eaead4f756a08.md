All four code references in the claim were verified against the actual source. Here is the result:

---

Audit Report

## Title
`gasLimitBucket` Token Leak When Per-Filter `THROTTLE` Bucket Is Exhausted in `ThrottleManagerImpl`

## Summary
In `ThrottleManagerImpl.throttle()`, global `gasLimitBucket` tokens are consumed before per-request filters are evaluated. When a `THROTTLE`-action filter's per-filter bucket is exhausted, `action()` throws a `ThrottleException` that exits `throttle()` without restoring the already-consumed `gasLimitBucket` tokens. The controller's catch block only restores tokens for `InvalidParametersException`, so the global gas bucket is permanently under-filled until natural refill.

## Finding Description

**Verified code path:**
`ContractController.call()` → `throttleManager.throttle(request)` → `ThrottleManagerImpl.throttle()` → `action()` → throws `ThrottleException`

**Step 1 — Gas tokens consumed unconditionally before filter loop:**

In `ThrottleManagerImpl.throttle()`, line 40 consumes `gasLimitBucket` tokens if the check passes: [1](#0-0) 

**Step 2 — Filter loop runs after gas is already consumed:** [2](#0-1) 

**Step 3 — `THROTTLE` branch throws `ThrottleException` when per-filter bucket is exhausted:** [3](#0-2) 

**Step 4 — `ContractController.call()` only catches `InvalidParametersException`; `ThrottleException` is never caught, so `restore()` is never called:** [4](#0-3) 

**Step 5 — `restore()` exists and is correct but is simply never invoked on this path:** [5](#0-4) 

**Failed assumption:** The design assumes a `ThrottleException` from `action()` means no gas was consumed, but gas was already consumed at line 40 before `action()` is ever reached.

Note: the same leak applies to the `REJECT` action (line 69), which also throws `ThrottleException` after gas has been consumed. [6](#0-5) 

## Impact Explanation
Each request that matches a `THROTTLE` filter while that filter's per-filter bucket is exhausted silently drains `gasLimitBucket` by `scaleGas(request.getGas())` tokens (where `scaleGas` divides by `GAS_SCALE_FACTOR = 10_000`) without restoration. [7](#0-6) 

Once the global gas bucket is depleted, all subsequent callers — regardless of whether they match the filter — receive "Gas per second rate limit exceeded" until the bucket naturally refills. Sustained at the maximum `requestsPerSecond` rate (default 500/sec), this becomes a continuous denial-of-service against the web3 API's gas rate limiter. [8](#0-7) 

## Likelihood Explanation
The precondition is that the operator has at least one `THROTTLE`-action filter configured in `throttleProperties.getRequest()`. [9](#0-8) 

This is a non-default but documented configuration option. An unprivileged external user needs no credentials — only knowledge of what request fields the filter matches (discoverable by probing). The per-filter bucket exhausts trivially with a handful of requests, and the attack is fully repeatable every second as the per-filter bucket refills.

## Recommendation
Add a `catch (ThrottleException e)` block in `ContractController.call()` that calls `throttleManager.restore(request.getGas())` before re-throwing, mirroring the existing `InvalidParametersException` handler:

```java
} catch (ThrottleException e) {
    throttleManager.restore(request.getGas());
    throw e;
}
```

Alternatively, move the `gasLimitBucket` consumption to after all per-request filters have been evaluated in `ThrottleManagerImpl.throttle()`, so gas is only consumed when the request is fully approved.

## Proof of Concept

1. Operator configures a `THROTTLE` filter matching requests to address `0xDEAD...` with `rate=5` (5 tokens/second).
2. Attacker sends 6 rapid POST `/api/v1/contracts/call` requests with `to=0xDEAD...` and `gas=15_000_000` (scales to 1,500 tokens).
3. Requests 1–5 pass both the global gas check and the per-filter bucket check — normal behavior.
4. Request 6: `rateLimitBucket.tryConsume(1)` passes; `gasLimitBucket.tryConsume(1500)` passes and **consumes 1,500 tokens**; the filter matches; `filter.getBucket().tryConsume(1)` returns `false`; `ThrottleException` is thrown.
5. `ContractController.call()` does not catch `ThrottleException`, so `restore()` is never called. The 1,500 tokens are permanently lost from `gasLimitBucket`.
6. Attacker repeats step 4 at up to 500 req/sec (the `requestsPerSecond` limit). Each cycle after the per-filter bucket refills, one more request leaks 1,500 tokens from the global gas bucket.
7. The global gas bucket (default capacity ~750,000 scaled tokens) is drained within seconds, causing all legitimate callers to receive "Gas per second rate limit exceeded." [10](#0-9)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L36-49)
```java
    @Override
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
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L58-64)
```java
    @Override
    public void restore(long gas) {
        long tokens = throttleProperties.scaleGas(gas);
        if (tokens > 0) {
            gasLimitBucket.addTokens(tokens);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L66-76)
```java
    private void action(RequestProperties filter, ContractCallRequest request) {
        switch (filter.getAction()) {
            case LOG -> log.info("{}", request);
            case REJECT -> throw new ThrottleException("Invalid request");
            case THROTTLE -> {
                if (!filter.getBucket().tryConsume(1)) {
                    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
                }
            }
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L46-50)
```java
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L31-32)
```java
    @NotNull
    private List<RequestProperties> request = List.of();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
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
