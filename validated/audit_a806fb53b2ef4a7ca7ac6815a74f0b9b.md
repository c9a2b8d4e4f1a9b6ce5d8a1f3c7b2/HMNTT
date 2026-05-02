All code references check out exactly against the repository. Here is the verified audit report:

---

Audit Report

## Title
Gas Token Leak via Unrestored Tokens When `action()` Throws `ThrottleException` After `gasLimitBucket` Consumption

## Summary
In `ThrottleManagerImpl.throttle()`, gas tokens are consumed from `gasLimitBucket` before per-request filter actions are evaluated. If a configured `REJECT` or exhausted `THROTTLE` filter subsequently throws a `ThrottleException`, `ContractController.call()` does not catch it and never calls `restore()`, permanently losing those gas tokens.

## Finding Description
**`ContractController.call()`** catches only `InvalidParametersException` and calls `restore()` exclusively for that exception type: [1](#0-0) 

`ThrottleException` is not caught anywhere in `call()`, and no global `@ExceptionHandler` exists in the codebase to intercept it and call `restore()`.

**`ThrottleManagerImpl.throttle()`** executes in this order:

1. **Line 38–39**: `rateLimitBucket.tryConsume(1)` — throws before gas is consumed. Safe.
2. **Line 40–42**: `gasLimitBucket.tryConsume(scaleGas(request.getGas()))` — gas tokens are **permanently consumed** on success.
3. **Lines 44–48**: Iterates `requestFilter` list and calls `action()`. [2](#0-1) 

**`action()`** throws `ThrottleException` unconditionally for `REJECT`, and for `THROTTLE` when the per-filter bucket is exhausted: [3](#0-2) 

When either branch throws, execution unwinds through `throttle()` back to `call()`. Because `ThrottleException` is not caught there, `restore()` is never invoked, and the gas tokens consumed at step 2 are permanently lost.

**`restore()`** correctly adds tokens back to `gasLimitBucket`, but is simply never reached on this code path: [4](#0-3) 

**Root cause**: The failed assumption is that a `ThrottleException` from `action()` means "no work was done, no resources were consumed." In reality, gas tokens were already consumed at line 40 before the filter loop runs.

## Impact Explanation
The `gasLimitBucket` is a shared, global resource governing how much gas all users can consume per second. Each request with gas = 15,000,000 (max) that matches a `REJECT` filter drains `scaleGas(15_000_000)` tokens from the shared budget without any actual EVM execution. Repeated exploitation exhausts the gas budget, causing all legitimate users to receive `"Gas per second rate limit exceeded."` errors — a complete DoS of the `/api/v1/contracts/call` endpoint.

## Likelihood Explanation
Exploitability requires a `REJECT` or `THROTTLE` filter to be configured in `hiero.mirror.web3.throttle.request`. The default is an empty list (`List.of()`), so default deployments are not affected. [5](#0-4) 

However, operators who configure `REJECT` filters to block known-bad contract addresses or calldata patterns expose themselves to this attack. Any attacker who can observe or guess those patterns can exploit this with no credentials, no special role, and no prior state — just repeated HTTP POST requests to a public endpoint.

## Recommendation
Extend the try-catch in `ContractController.call()` to also catch `ThrottleException` and call `restore()` before re-throwing:

```java
} catch (ThrottleException e) {
    throttleManager.restore(request.getGas());
    throw e;
}
```

Alternatively, restructure `ThrottleManagerImpl.throttle()` to evaluate all filters **before** consuming gas tokens, so that a `ThrottleException` from `action()` is thrown before any gas is consumed — making the ordering consistent with the existing assumption.

## Proof of Concept
1. Configure a `REJECT` filter matching a specific `to` address (e.g., `0xdeadbeef...`).
2. Send repeated POST requests to `/api/v1/contracts/call` with `"to": "0xdeadbeef..."` and `"gas": 15000000`.
3. Each request: `rateLimitBucket` consumes 1 token, `gasLimitBucket` consumes `scaleGas(15_000_000)` tokens, then `action()` throws `ThrottleException("Invalid request")`.
4. `restore()` is never called; gas tokens are permanently lost.
5. After enough requests, `gasLimitBucket` is exhausted; all subsequent legitimate requests receive `"Gas per second rate limit exceeded."` until the bucket refills.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L39-50)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L32-32)
```java
    private List<RequestFilter> filters = List.of();
```
