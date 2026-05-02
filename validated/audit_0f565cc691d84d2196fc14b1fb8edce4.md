The code references are accurate and verifiable. Let me confirm the exact behavior before rendering a verdict.

**Verified facts from the actual code:**

1. `ThrottleManagerImpl.throttle()` loop at lines 44–48 has no `break` after `action()` — confirmed. [1](#0-0) 

2. `action()` THROTTLE branch consumes a token and returns normally; REJECT throws — confirmed. [2](#0-1) 

3. `restore()` only adds tokens back to `gasLimitBucket`; per-filter THROTTLE buckets are never restored — confirmed. [3](#0-2) 

4. `RequestProperties.test()` returns `true` if ANY filter in the list matches, and the probabilistic rate check is **skipped entirely** for THROTTLE entries (`action != ActionType.THROTTLE` guard at line 50) — confirmed. [4](#0-3) 

5. THROTTLE bucket capacity and refill rate are both capped at `rate` ≤ 100 (`@Max(100)`), while the global `requestsPerSecond` defaults to 500 — confirmed. [5](#0-4) [6](#0-5) 

**SECURITY.md scope check:** The exclusion "Impacts that only require DDoS" does not apply here — the attack exploits a specific code-logic flaw (token consumed before REJECT fires) rather than volumetric flooding. The finding is in scope.

---

## Audit Report

## Title
THROTTLE Token Consumed Before REJECT Filter Fires, Enabling Targeted Bucket Depletion

## Summary
`ThrottleManagerImpl.throttle()` iterates all configured `RequestProperties` entries without breaking after a `THROTTLE` action succeeds. When a THROTTLE entry precedes a REJECT entry with overlapping match criteria, a single request consumes one token from the THROTTLE bucket and is then immediately rejected. Because `restore()` only replenishes the global `gasLimitBucket`, the consumed THROTTLE token is permanently lost. An attacker can exploit this to continuously drain the THROTTLE bucket, causing legitimate users matching only the THROTTLE criteria to receive spurious HTTP 429 responses.

## Finding Description

**Exact code path**

`ThrottleManagerImpl.throttle()` (lines 44–48) iterates all `RequestProperties` entries in declaration order with no early exit after a successful THROTTLE action:

```java
for (var requestFilter : throttleProperties.getRequest()) {
    if (requestFilter.test(request)) {
        action(requestFilter, request);   // no break — loop continues
    }
}
``` [1](#0-0) 

`action()` handles THROTTLE by consuming one token from the per-filter `Bucket` and returning normally, allowing the loop to advance to the next entry:

```java
case THROTTLE -> {
    if (!filter.getBucket().tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
``` [7](#0-6) 

If the next matching entry has action `REJECT`, it throws immediately:

```java
case REJECT -> throw new ThrottleException("Invalid request");
``` [8](#0-7) 

`restore()` only adds tokens back to the global `gasLimitBucket`; it has no knowledge of per-filter buckets and is never called on a REJECT path:

```java
public void restore(long gas) {
    long tokens = throttleProperties.scaleGas(gas);
    if (tokens > 0) {
        gasLimitBucket.addTokens(tokens);
    }
}
``` [3](#0-2) 

**Root cause / failed assumption**

The code implicitly assumes that `RequestProperties` entries in the list are mutually exclusive — a request will match at most one entry. This assumption is neither enforced in configuration validation nor in the loop itself. When two entries overlap, the THROTTLE entry silently pre-charges the attacker before the REJECT entry fires.

An additional contributing factor: `RequestProperties.test()` skips the probabilistic rate-sampling check entirely for THROTTLE entries (line 50 guard `action != ActionType.THROTTLE`), meaning every matching request deterministically consumes a token: [9](#0-8) 

**Exploit configuration**

```yaml
hiero.mirror.web3.throttle.request:
  - action: THROTTLE        # entry 0 — rate-limit all "latest" block queries
    rate: 50
    filters:
      - field: BLOCK
        type: EQUALS
        expression: latest
  - action: REJECT          # entry 1 — block a known-bad data pattern
    filters:
      - field: DATA
        type: CONTAINS
        expression: deadbeef
```

Attacker sends requests with `block=latest` **and** `data=...deadbeef...`:

1. Global `rateLimitBucket.tryConsume(1)` → passes.
2. Global `gasLimitBucket.tryConsume(...)` → passes (low gas value).
3. Entry 0 (`THROTTLE`, `block=latest`) matches → `filter.getBucket().tryConsume(1)` succeeds → **1 THROTTLE token consumed**.
4. Entry 1 (`REJECT`, `data contains deadbeef`) matches → `ThrottleException("Invalid request")` thrown.
5. Attacker receives HTTP 429; THROTTLE token is permanently gone.

## Impact Explanation

An unprivileged attacker can continuously starve the THROTTLE bucket for a class of legitimate requests (e.g., all `block=latest` queries). The THROTTLE bucket capacity is capped at `rate` ≤ 100 tokens (enforced by `@Max(100)`) and refills at `rate` tokens/second: [10](#0-9) 

The global rate limit defaults to 500 req/s: [6](#0-5) 

An attacker sending 100 req/s (well within the global limit) drains the 100-token THROTTLE bucket as fast as it refills, keeping it perpetually empty. Legitimate users sending `block=latest` requests without the bad data pattern receive spurious HTTP 429 responses — a targeted denial-of-service against a specific request category. The global `rateLimitBucket` and `gasLimitBucket` tokens are also consumed without any useful work being done.

## Likelihood Explanation

The attack requires a configuration where a THROTTLE entry precedes a REJECT entry with overlapping match criteria — a plausible operational setup (broad throttle + narrow block-list). The attacker needs only to observe or guess the filter fields (`BLOCK`, `DATA`, `FROM`, `TO`, `GAS`, `VALUE`, `ESTIMATE` — a small, documented enum) and craft requests accordingly. No authentication, special privileges, or on-chain access is required. The attack is fully repeatable and automatable with a simple HTTP client.

## Recommendation

1. **Break after the first matching action in the loop.** If a request matches a THROTTLE or REJECT entry, stop processing further entries:
   ```java
   for (var requestFilter : throttleProperties.getRequest()) {
       if (requestFilter.test(request)) {
           action(requestFilter, request);
           break; // stop after first match
       }
   }
   ```
2. **Restore per-filter THROTTLE tokens on REJECT.** Track which THROTTLE buckets were charged during the loop and restore them if a subsequent REJECT fires.
3. **Add configuration validation** that warns or rejects configurations where a THROTTLE entry precedes a REJECT entry with potentially overlapping filter criteria.

## Proof of Concept

Using the overlapping configuration above, the following sequence demonstrates bucket depletion (pseudocode):

```
# Attacker loop (runs at ~100 req/s, within global 500 req/s limit)
for i in range(1000):
    POST /api/v1/contracts/call
    body: { "block": "latest", "data": "0xdeadbeef", "gas": 21000 }
    # Response: 429 "Invalid request" (REJECT fires)
    # But THROTTLE token was consumed before REJECT

# After ~1 second, THROTTLE bucket (capacity=50, refill=50/s) is perpetually empty

# Legitimate user
POST /api/v1/contracts/call
body: { "block": "latest", "data": "0xabcdef", "gas": 21000 }
# Response: 429 "Requests per second rate limit exceeded"
# Legitimate user is denied despite never sending bad data
```

The THROTTLE token consumed at line 71 of `ThrottleManagerImpl.java` is never returned because `restore()` at lines 59–64 only operates on `gasLimitBucket`, and the REJECT path at line 69 throws before any cleanup can occur. [11](#0-10)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L44-48)
```java
        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L37-39)
```java
    @Min(0)
    @Max(100)
    private long rate = 100;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L63-69)
```java
    private Bucket createBucket() {
        final var bandwidth = Bandwidth.builder()
                .capacity(rate)
                .refillGreedy(rate, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(bandwidth).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
