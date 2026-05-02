### Title
Unconditional Counter Increment in `RequestProperties.test()` Enables Filter Exhaustion by Unprivileged Users

### Summary
`RequestProperties.test()` calls `counter.getAndIncrement()` unconditionally at the top of the method, before any filter-matching logic is evaluated. This means every incoming request — regardless of whether it matches the configured filter criteria — consumes one unit from the `limit` budget. An unprivileged attacker can deliberately exhaust this counter, permanently disabling the filter for all subsequent users until the service is restarted or reconfigured.

### Finding Description

**Exact code location:**
`web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java`, `test()`, line 46:

```java
if (rate == 0 || counter.getAndIncrement() >= limit) {
    return false;
}
```

The counter is incremented **before** the random-rate sampling check (line 50) and **before** any `RequestFilter` in the `filters` list is evaluated (lines 54–58). A request that does not match any filter still increments the counter and returns `false` at line 58 (or line 60 if `filters` is empty). The counter is never decremented.

**Call path:**
`ThrottleManagerImpl.throttle()` (line 44–48) iterates over every configured `RequestProperties` and calls `requestFilter.test(request)` for each one. Every request that clears the global `rateLimitBucket` and `gasLimitBucket` checks will reach this loop and increment the counter of every filter, whether or not the request matches that filter's criteria.

**Failed assumption:**
The design assumes `limit` acts as "how many times this filter has been triggered." In reality it acts as "how many times `test()` has been called," which includes all non-matching traffic.

### Impact Explanation

When an operator configures a `RequestProperties` entry with:
- `action = REJECT` and a finite `limit` — an attacker exhausts the counter, the filter permanently returns `false`, and requests that should have been rejected are now accepted.
- `action = THROTTLE` and a finite `limit` — the per-filter rate-limiting bucket is bypassed entirely after exhaustion.
- `action = LOG` — audit/logging coverage is silently dropped.

The `REJECT` case is the most severe: it constitutes a security-control bypass achievable by any unauthenticated caller. The scope label "griefing with no economic damage" applies to the LOG/THROTTLE cases; the REJECT case can escalate beyond griefing.

### Likelihood Explanation

- **No privileges required.** Any caller that can reach the web3 JSON-RPC endpoint can trigger this.
- **Rate-limited but not prevented.** The global `rateLimitBucket` (default 500 req/s, `ThrottleProperties` line 35) slows exhaustion but does not stop it. A `limit` of 50,000 is exhausted in 100 seconds at the default rate.
- **Repeatable.** The counter never resets at runtime; once exhausted the filter stays disabled until process restart.
- **Requires non-default config.** The default `limit` is `Long.MAX_VALUE` (line 35 of `RequestProperties.java`), which is unreachable in practice. The vulnerability is only exploitable when an operator explicitly sets a finite `limit`. This is a documented, valid configuration option, so real deployments that use it are at risk.

### Recommendation

Move `counter.getAndIncrement()` to **after** all filter predicates have matched, so the counter only advances when the filter actually fires:

```java
@Override
public boolean test(ContractCallRequest contractCallRequest) {
    if (rate == 0) {
        return false;
    }
    if (action != ActionType.THROTTLE && RandomUtils.secure().randomLong(0L, 100L) >= rate) {
        return false;
    }
    boolean matched = filters.isEmpty() ||
        filters.stream().anyMatch(f -> f.test(contractCallRequest));
    if (!matched) {
        return false;
    }
    // Only now consume from the limit budget
    return counter.getAndIncrement() < limit;
}
```

This ensures `limit` semantically means "number of times this filter matched and acted," not "number of times any request was evaluated."

### Proof of Concept

**Preconditions:**
- A `RequestProperties` entry is configured with `action=REJECT`, a specific filter (e.g., `field=FROM, type=EQUALS, expression=0xDeadBeef…`), and `limit=1000`.
- The attacker does **not** control the `from` address `0xDeadBeef…`.

**Steps:**
1. Attacker sends 1,000 arbitrary `eth_call` requests with any `from` address other than `0xDeadBeef…`. Each request passes the global rate limit, enters `throttle()`, and calls `requestFilter.test()`. The counter increments to 1,000 on each call even though no request matches the filter.
2. After 1,000 requests (≈2 seconds at 500 req/s), `counter >= limit` is true.
3. The legitimate target address `0xDeadBeef…` now sends a request. `test()` returns `false` immediately at line 46 (counter already at limit), the `REJECT` action is never triggered, and the request is processed normally.

**Result:** The REJECT filter is permanently disabled; the protected address can now transact freely. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L34-36)
```java
    @PositiveOrZero
    private long limit = Long.MAX_VALUE;

```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L45-48)
```java
    public boolean test(ContractCallRequest contractCallRequest) {
        if (rate == 0 || counter.getAndIncrement() >= limit) {
            return false;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
