The code has been verified. All technical claims in the report are confirmed against the actual source.

**Verified facts:**
- `counter.getAndIncrement()` is called at line 46, unconditionally, before the filter loop at lines 54–58 — confirmed in `RequestProperties.java`
- `limit` defaults to `Long.MAX_VALUE` (line 35) — confirmed
- `ThrottleManagerImpl.throttle()` only calls `action()` when `test()` returns `true` (lines 44–48) — confirmed
- The `AtomicLong counter` has no reset mechanism — confirmed
- The `requestLimitReached` test (`limit=0`) confirms that once exhausted, the request passes through silently — confirmed

---

## Audit Report

## Title
Counter Exhaustion via Non-Matching Requests Bypasses `RequestProperties` Filter Actions (REJECT/THROTTLE)

## Summary
In `RequestProperties.test()`, the `AtomicLong counter` is incremented unconditionally on every invocation before the filter-matching loop is evaluated. When an operator configures a finite `limit`, an attacker can exhaust the counter by flooding the endpoint with requests that do not match any configured filter. Once `counter >= limit`, `test()` permanently returns `false` for all subsequent requests — including legitimate ones that would have matched — silently disabling the configured `REJECT` or `THROTTLE` action.

## Finding Description

In `web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java`, the `test()` method increments the counter before evaluating any filter: [1](#0-0) 

The condition `counter.getAndIncrement() >= limit` at line 46 fires on every call to `test()`, regardless of whether the request satisfies any `RequestFilter`. The filter loop at lines 54–58 is only reached after the counter has already been incremented. This means every call to `test()` — matching or not — consumes one unit of the `limit` budget.

In `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, `action()` is only invoked when `test()` returns `true`: [2](#0-1) 

Once the counter is exhausted, `test()` short-circuits at line 46 and returns `false` permanently, so `action()` is never reached for any subsequent request — including those that would have matched the configured filter.

The `AtomicLong counter` is initialized once and never reset: [3](#0-2) 

The default value of `limit` is `Long.MAX_VALUE`, which prevents exploitation in default configurations: [4](#0-3) 

However, any operator-configured finite `limit` is vulnerable. The existing test `requestLimitReached` confirms the intended behavior when the limit is reached is to silently pass the request through: [5](#0-4) 

**Root cause:** `counter.getAndIncrement()` is evaluated unconditionally on every invocation of `test()`, regardless of whether the request satisfies any `RequestFilter`. The `limit` field is intended to cap how many times the filter rule fires, but because the counter is incremented before filter matching, non-matching requests consume the budget.

**Failed assumption:** The design assumes the counter tracks "how many times this filter matched and acted upon a request," but it actually tracks "how many times `test()` was called at all."

## Impact Explanation

- **`action=REJECT`:** A security rule blocking a specific caller, contract address, or calldata pattern is permanently disabled after counter exhaustion. Requests from the previously-blocked address now pass through to execution.
- **`action=THROTTLE`:** A per-pattern rate limit is permanently disabled; the attacker can send unlimited matching requests without hitting the per-filter bucket.
- **`action=LOG`:** Audit/monitoring coverage is silently dropped, enabling undetected abuse.

Severity is **High** when `limit` is finite and `action` is `REJECT` or `THROTTLE`, as it constitutes a complete bypass of an operator-configured security control.

## Likelihood Explanation

- **Precondition:** Operator must configure a finite `limit`. This is a realistic operational choice (e.g., "apply this block rule for the first N requests of the day").
- **Attacker capability:** Zero privilege required. Any user who can call the web3 endpoint can send arbitrary `ContractCallRequest` payloads.
- **Detectability:** The bypass is silent — no error is thrown, no log is emitted once the counter is exhausted.
- **Repeatability:** The `AtomicLong counter` is never reset (no TTL, no refill), so exhaustion is permanent until the service restarts.
- **Cost:** The attacker only needs to send `limit` cheap, non-matching requests. With `requestsPerSecond=500` (default), exhausting a `limit=10000` counter takes approximately 20 seconds of sustained requests.

## Recommendation

Move `counter.getAndIncrement()` to after the filter-matching loop, so the counter is only incremented when a request actually matches a configured filter:

```java
@Override
public boolean test(ContractCallRequest contractCallRequest) {
    if (rate == 0) {
        return false;
    }

    if (action != ActionType.THROTTLE && RandomUtils.secure().randomLong(0L, 100L) >= rate) {
        return false;
    }

    boolean matched = filters.isEmpty();
    for (var filter : filters) {
        if (filter.test(contractCallRequest)) {
            matched = true;
            break;
        }
    }

    if (matched && counter.getAndIncrement() >= limit) {
        return false;
    }

    return matched;
}
```

This ensures the `limit` budget is consumed only when a request matches the configured filter, aligning the counter semantics with the intended "how many times this rule fired" meaning.

## Proof of Concept

1. Configure a `RequestProperties` entry with `action=REJECT`, `filters=[{field=FROM, type=EQUALS, expression=0xVictimAddress}]`, and `limit=10000`.
2. Send 10,000 requests from any address other than `0xVictimAddress`. Each call to `test()` increments the counter but returns `false` (no filter match), so `action()` is never called — the requests pass through normally.
3. After 10,000 iterations, `counter.getAndIncrement() >= limit` is permanently `true`.
4. Send a request from `0xVictimAddress`. `test()` returns `false` immediately at line 46 — the `REJECT` action is never invoked. The previously-blocked address is now unblocked. [6](#0-5) [7](#0-6)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L26-26)
```java
    private final AtomicLong counter = new AtomicLong(0L);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L34-35)
```java
    @PositiveOrZero
    private long limit = Long.MAX_VALUE;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L44-61)
```java
    @Override
    public boolean test(ContractCallRequest contractCallRequest) {
        if (rate == 0 || counter.getAndIncrement() >= limit) {
            return false;
        }

        if (action != ActionType.THROTTLE && RandomUtils.secure().randomLong(0L, 100L) >= rate) {
            return false;
        }

        for (var filter : filters) {
            if (filter.test(contractCallRequest)) {
                return true;
            }
        }

        return filters.isEmpty();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L44-48)
```java
        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
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

**File:** web3/src/test/java/org/hiero/mirror/web3/throttle/ThrottleManagerImplTest.java (L185-190)
```java
    void requestLimitReached() {
        requestProperties.setAction(ActionType.REJECT);
        requestProperties.setLimit(0L);
        var request = request();
        throttleManager.throttle(request);
    }
```
