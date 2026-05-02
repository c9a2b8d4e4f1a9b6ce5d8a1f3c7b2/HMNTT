### Title
Shared Per-Filter Throttle Bucket Allows Unprivileged User to Exhaust Rate Limit and Deny Service to Legitimate Users

### Summary
`ThrottleManagerImpl.action()` uses a single shared `Bucket` per `RequestProperties` entry with no per-source (IP/caller) isolation. An unprivileged attacker who knows (or can guess) a configured filter expression can deliberately send matching requests at a rate just above the configured `rate` limit, exhausting the shared bucket and causing all other legitimate users whose requests match the same filter to receive `ThrottleException`, effectively blocking their transactions.

### Finding Description

**Code path:**

`ThrottleManagerImpl.throttle()` iterates over all configured `RequestProperties`: [1](#0-0) 

For each matching filter, `action()` is called: [2](#0-1) 

The `THROTTLE` branch calls `filter.getBucket().tryConsume(1)`. The bucket is created lazily and **shared globally** across all callers: [3](#0-2) [4](#0-3) 

The bucket capacity and refill rate are both set to `rate`. With `rate=1` (the minimum non-zero value allowed by `@Min(0) @Max(100)`), the bucket holds exactly 1 token and refills at 1 token/second.

**Critical design flaw in `RequestProperties.test()`:** For `action=THROTTLE`, the random sampling check is explicitly skipped: [5](#0-4) 

This means every request matching the filter unconditionally consumes from the shared bucket. There is no per-IP, per-session, or per-caller sub-bucket.

**Filter matching is on user-controlled fields** (`DATA`, `FROM`, `TO`, `VALUE`, `GAS`, `ESTIMATE`, `BLOCK`): [6](#0-5) 

An attacker controls all of these fields in a `ContractCallRequest`.

**Root cause:** The assumption that the per-filter `Bucket` acts as a fair shared resource fails because there is no mechanism to prevent a single caller from consuming all tokens, starving all other callers.

### Impact Explanation

If an operator configures a `RequestProperties` with `action=THROTTLE`, `rate=1`, and a filter matching a common pattern (e.g., `field=DATA, type=CONTAINS, expression="0xa9059cbb"` for ERC-20 transfers, or `field=TO` matching a popular contract address), an attacker sending just 2 matching requests per second will continuously exhaust the 1-token bucket. Every legitimate user whose request matches the same filter receives `ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED)` and cannot confirm their transaction. This is a targeted, low-effort denial of service against a specific transaction class or contract.

### Likelihood Explanation

**Precondition:** An operator must have configured at least one `RequestProperties` with `action=THROTTLE` and a low `rate`. The default is an empty list, so this requires deliberate admin configuration. However, the entire purpose of the THROTTLE action is to be used by operators to rate-limit specific request patterns — making such configuration expected in production deployments.

**Attacker capability:** No privileges required. The attacker only needs to:
1. Identify the filter expression (discoverable by observing which requests get throttled, or by reading public documentation/config).
2. Send requests at a rate of 2/second — well within the global 500 req/s limit — to continuously starve the shared bucket.

The global `rateLimitBucket` (500 req/s default) provides no protection here since the attacker's 2 req/s is far below it: [7](#0-6) 

The attack is repeatable indefinitely and requires no authentication.

### Recommendation

1. **Per-source bucket isolation:** Replace the single shared `Bucket` with a `CaffeineProxyManager` or similar `ProxyManager<String>` keyed by caller IP (or `from` address), so each source has its own token bucket. This is natively supported by bucket4j.
2. **Separate `rate` semantics:** The `rate` field currently conflates sampling percentage (for LOG/REJECT) with bucket capacity (for THROTTLE). Introduce a dedicated `requestsPerSecond` field for THROTTLE to avoid confusion and misconfiguration.
3. **Minimum rate enforcement:** Enforce a meaningful minimum (e.g., `@Min(10)`) for THROTTLE buckets to reduce the blast radius of misconfiguration.

### Proof of Concept

**Precondition:** Operator has configured:
```yaml
hiero.mirror.web3.throttle.request:
  - action: THROTTLE
    rate: 1
    filters:
      - field: DATA
        type: CONTAINS
        expression: "0xa9059cbb"
```

**Attacker script (pseudo-code):**
```python
import time, requests

while True:
    requests.post("/api/v1/contracts/call", json={
        "data": "0xa9059cbb000000000000000000000000<addr><amount>",
        "to": "<any_address>"
    })
    requests.post("/api/v1/contracts/call", json={
        "data": "0xa9059cbb000000000000000000000000<addr><amount>",
        "to": "<any_address>"
    })
    time.sleep(1)
```

**Result:** The attacker sends 2 requests/second. The first consumes the 1 token; the second is rejected. The bucket refills 1 token/second, which the attacker immediately consumes again. Any legitimate user sending an ERC-20 transfer call receives `HTTP 429 ThrottleException("Requests per second rate limit exceeded")` and cannot confirm their transaction.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L38-39)
```java
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L41-42)
```java
    @Getter(lazy = true)
    private final Bucket bucket = createBucket();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L50-52)
```java
        if (action != ActionType.THROTTLE && RandomUtils.secure().randomLong(0L, 100L) >= rate) {
            return false;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L39-46)
```java
    enum FilterField {
        BLOCK(ContractCallRequest::getBlock),
        DATA(ContractCallRequest::getData),
        ESTIMATE(ContractCallRequest::isEstimate),
        FROM(ContractCallRequest::getFrom),
        GAS(ContractCallRequest::getGas),
        TO(ContractCallRequest::getTo),
        VALUE(ContractCallRequest::getValue);
```
