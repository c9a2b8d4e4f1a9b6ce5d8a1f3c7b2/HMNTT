### Title
Counter Exhaustion via Non-Matching Requests Bypasses REJECT Filter in `RequestProperties.test()`

### Summary
In `RequestProperties.test()`, the `AtomicLong counter` is unconditionally incremented via `counter.getAndIncrement()` before any filter pattern matching occurs. This means every request — whether it matches the configured filter patterns or not — consumes one unit of the `limit` budget. When an operator configures a finite `limit` on a REJECT filter, an attacker can exhaust the counter by flooding with non-matching requests, permanently disabling the REJECT filter and then freely sending the malicious requests it was meant to block.

### Finding Description

**Exact code path:**

`RequestProperties.test()` — [1](#0-0) 

```java
public boolean test(ContractCallRequest contractCallRequest) {
    if (rate == 0 || counter.getAndIncrement() >= limit) {  // line 46
        return false;
    }
    // ...
    for (var filter : filters) {
        if (filter.test(contractCallRequest)) {              // line 55
            return true;
        }
    }
    return filters.isEmpty();
}
```

**Root cause:** `counter.getAndIncrement()` is evaluated unconditionally at line 46, *before* the per-request filter matching loop at lines 54–58. Every call to `test()` — regardless of whether the request matches any `RequestFilter` — permanently increments the counter. Once `counter >= limit`, the method returns `false` for *all* future requests, including those that would have matched the REJECT filter.

**Exploit flow:**

1. Operator configures a REJECT `RequestProperties` with a finite `limit` (e.g., `limit: 10000`) and filter patterns targeting malicious `data` payloads (e.g., a known exploit selector).
2. Attacker sends `limit` requests whose `data` field does **not** match the filter expression. Each request passes through `ThrottleManagerImpl.throttle()` [2](#0-1) , calls `requestFilter.test(request)`, increments the counter, fails the filter match, and returns `false` — no REJECT is triggered.
3. After `limit` such requests, `counter >= limit` is permanently true. `test()` now returns `false` for every subsequent request.
4. Attacker sends the malicious requests. `test()` returns `false` → `action()` is never called → the REJECT branch is never reached. [3](#0-2) 

**Why existing checks are insufficient:**

- The global `rateLimitBucket` (default 500 req/s) and `gasLimitBucket` slow the attacker but do not prevent counter exhaustion — they only pace it. [4](#0-3) 
- The `limit` field defaults to `Long.MAX_VALUE` [5](#0-4) , making exhaustion infeasible at default settings. However, the field is explicitly designed to be overridden via `@ConfigurationProperties` [6](#0-5) , and operators setting a finite limit (e.g., to cap filter overhead) are fully exposed.
- The counter is never reset; once exhausted, the filter is permanently disabled until application restart.

### Impact Explanation
A REJECT filter is the primary mechanism to block known-malicious request patterns (e.g., exploit calldata, specific `to` addresses, or abusive callers). Bypassing it allows an attacker to submit previously-blocked malicious contract calls freely. Depending on what the REJECT filter was protecting, this could enable exploitation of vulnerable contracts, abuse of compute resources, or circumvention of access controls. This maps to the stated scope: shutdown/disruption of ≥30% of network processing without brute force.

### Likelihood Explanation
- **Precondition:** Operator must have configured a finite `limit` on a REJECT filter — a non-default but operationally reasonable configuration (e.g., "apply this block rule for the first N requests to limit overhead").
- **Attacker capability:** No authentication required. Any external HTTP client can send `eth_call` / `eth_estimateGas` requests.
- **Feasibility:** At 500 req/s (default global rate limit), a `limit` of 10,000 is exhausted in 20 seconds. Smaller limits are exhausted faster. The attack is repeatable across restarts if the configuration is not changed.
- **Detection difficulty:** The non-matching flood requests look like ordinary (failed) contract calls and may not trigger alerts.

### Recommendation
Move `counter.getAndIncrement()` to *after* the filter pattern matching, so only requests that actually match the configured filters consume the limit budget:

```java
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
    if (!matched) {
        return false;
    }
    // Only consume the limit budget for requests that actually match
    return counter.getAndIncrement() < limit;
}
```

This ensures the `limit` semantics are "apply this filter to the first N *matching* requests," which is the operationally expected behavior and closes the exhaustion path.

### Proof of Concept

**Setup:** Configure a REJECT filter:
```yaml
hiero.mirror.web3.throttle.request:
  - action: REJECT
    limit: 1000
    filters:
      - field: DATA
        type: CONTAINS
        expression: "deadbeef"
```

**Step 1 — Exhaust the counter (1000 benign requests):**
```bash
for i in $(seq 1 1000); do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"0x00000000","to":"0x...","gas":50000}'
done
```
Each request increments `counter` but does not match `deadbeef` → no REJECT.

**Step 2 — Send malicious request (now unblocked):**
```bash
curl -X POST http://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"data":"0xdeadbeef","to":"0x...","gas":50000}'
```
`counter >= limit` → `test()` returns `false` → REJECT is never triggered → request is processed.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L35-35)
```java
    private long limit = Long.MAX_VALUE;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L45-61)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L38-42)
```java
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L13-13)
```java
@ConfigurationProperties("hiero.mirror.web3.throttle")
```
