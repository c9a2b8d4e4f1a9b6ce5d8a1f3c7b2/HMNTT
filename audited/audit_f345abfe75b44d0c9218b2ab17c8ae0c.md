### Title
Shared THROTTLE Bucket Starvation Allows Single Unprivileged User to Deny Service to All Other Users Matching the Same Filter

### Summary
The `action()` method in `ThrottleManagerImpl` enforces per-filter throttling using a single globally-shared `Bucket` instance stored in `RequestProperties`. Because there is no per-user, per-IP, or per-session isolation within the THROTTLE bucket, a single unprivileged attacker who crafts requests matching the filter's criteria and submits them at exactly the bucket's refill rate can continuously drain all available tokens, leaving zero tokens for every other user whose requests match the same filter. The global rate limit (`rateLimitBucket`, default 500 req/sec) is far higher than the per-filter bucket capacity (default 100 tokens/sec), so it provides no meaningful protection against this starvation attack.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.throttle()` (lines 44–48) iterates over all configured `RequestProperties` filters and calls `action(requestFilter, request)` for each one that matches:

```java
for (var requestFilter : throttleProperties.getRequest()) {
    if (requestFilter.test(request)) {
        action(requestFilter, request);
    }
}
```

`action()` (lines 70–74) for `ActionType.THROTTLE` calls `tryConsume(1)` on the filter's single shared bucket:

```java
case THROTTLE -> {
    if (!filter.getBucket().tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

`RequestProperties.createBucket()` (lines 63–69) creates **one** bucket instance per filter, shared across all callers:

```java
private Bucket createBucket() {
    final var bandwidth = Bandwidth.builder()
            .capacity(rate)
            .refillGreedy(rate, Duration.ofSeconds(1))
            .build();
    return Bucket.builder().addLimit(bandwidth).build();
}
```

The `@Getter(lazy = true)` annotation on line 41 ensures this single instance is reused for every request that matches the filter — there is no per-caller bucket.

**Root cause / failed assumption:**

The design assumes that the THROTTLE bucket limits the aggregate rate of a class of requests. The failed assumption is that no single caller can monopolize the entire token budget. In reality, because the bucket is shared with no per-user fairness, one attacker sending requests at exactly `rate` tokens/second drains the bucket as fast as it refills, leaving 0 tokens for all other users.

**Why the existing checks are insufficient:**

- The global `rateLimitBucket` (default 500 req/sec, `ThrottleProperties` line 35) is much larger than the per-filter bucket (default capacity = `rate` = 100). An attacker can send 100 req/sec — well within the global limit — and fully starve the per-filter bucket.
- The `limit` field (default `Long.MAX_VALUE`, line 35 of `RequestProperties`) provides no meaningful cap.
- The random-sampling guard on line 50 of `RequestProperties.test()` is explicitly **skipped** for `ActionType.THROTTLE` (`action != ActionType.THROTTLE`), so every matching request unconditionally hits the shared bucket.
- If the operator configures a THROTTLE filter with an empty `filters` list, line 60 (`return filters.isEmpty()`) causes **every** request to match, making the attack trivially universal.

**Exploit flow:**

1. Attacker observes or discovers the filter criteria (e.g., a specific `to` address, `data` prefix, or `block` value) — these are operator-configured strings matched case-insensitively via `CONTAINS` or `EQUALS`.
2. Attacker crafts `ContractCallRequest` objects satisfying the filter (e.g., sets `to` to the target contract address).
3. Attacker sends exactly `rate` such requests per second (e.g., 100/sec with default config), staying within the global 500 req/sec limit.
4. Each request consumes 1 token; the bucket refills at `rate` tokens/sec. The attacker's steady-state consumption equals the refill rate → bucket stays at 0.
5. Any concurrent legitimate user whose request matches the same filter gets `tryConsume(1) == false` → `ThrottleException("Requests per second rate limit exceeded")` → HTTP 429.

### Impact Explanation

All legitimate users whose requests match the targeted THROTTLE filter are completely denied service for the duration of the attack. The attacker does not need any credentials, API keys, or elevated privileges — only knowledge of the filter's matching criteria. If the filter has no sub-filters (`filters.isEmpty()`), the attack affects every user of the endpoint. This is a targeted, sustained, low-cost denial-of-service against a specific request class.

### Likelihood Explanation

The attack requires no authentication and no special tooling — a simple HTTP client sending 100 requests/second is sufficient. Filter criteria (contract address, data prefix, block tag) are often publicly known or easily enumerable. The attack is repeatable indefinitely and requires no state beyond the request template. A motivated attacker (e.g., a competitor, a griefing actor) can sustain it with minimal infrastructure.

### Recommendation

Introduce per-caller rate limiting within the THROTTLE path. Concretely:

1. **Per-IP bucket map**: Replace the single `Bucket` in `RequestProperties` with a `ConcurrentHashMap<String, Bucket>` keyed by caller IP (extracted from the HTTP request context). Each IP gets its own bucket with capacity `rate / expectedConcurrentUsers` or a configurable per-IP cap.
2. **Alternatively, use a sliding-window per-IP limiter** (e.g., Bucket4j's `ProxyManager` backed by a local or distributed cache) so that one IP cannot consume more than its fair share.
3. **Add a per-IP sub-limit** to the existing global THROTTLE bucket: enforce both a global `rate` cap and a per-IP cap (e.g., `rate / 10`), so no single caller can exhaust the global budget.
4. **Operator guidance**: Document that THROTTLE filters with `filters.isEmpty()` apply to all traffic and are especially sensitive to this attack.

### Proof of Concept

Assume operator config:
```yaml
hiero.mirror.web3.throttle:
  requestsPerSecond: 500
  request:
    - action: THROTTLE
      rate: 10
      filters:
        - field: TO
          type: EQUALS
          expression: "0x00000000000000000000000000000000000004e4"
```

Attacker script (pseudo-code):
```python
import time, requests

url = "http://mirror-node/api/v1/contracts/call"
body = {"to": "0x00000000000000000000000000000000000004e4", "gas": 21000, "block": "latest"}

while True:
    for _ in range(10):          # 10 req/sec == refill rate
        requests.post(url, json=body)
    time.sleep(1)
```

Expected result:
- Attacker's 10 requests/sec all succeed (200 OK) — they consume tokens as fast as they refill.
- Any other user sending a request to the same `to` address during this window receives HTTP 429 `Requests per second rate limit exceeded`.
- Verified by the existing test `requestThrottled` in `ThrottleManagerImplTest` (lines 140–150), which demonstrates that a second request with `rate=1` is immediately rejected — the same effect an attacker achieves at scale against other users.