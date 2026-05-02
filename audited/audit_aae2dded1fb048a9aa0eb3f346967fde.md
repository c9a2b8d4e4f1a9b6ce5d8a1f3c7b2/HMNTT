### Title
Multi-Filter THROTTLE Bucket Drain via Single Crafted Request

### Summary
`ThrottleManagerImpl.throttle()` iterates all configured `RequestProperties` without stopping at the first match, calling `action()` for every matching entry. When multiple `RequestProperties` entries have `ActionType.THROTTLE` and overlapping filter criteria, a single crafted request consumes one token from each matching per-filter bucket simultaneously. An unprivileged attacker can exploit this to drain N independent THROTTLE buckets using only 1 global-rate-limit token per request, denying service to legitimate users whose requests match those filters.

### Finding Description
**Exact code path:**

`ThrottleManagerImpl.throttle()` (lines 44–48) iterates every `RequestProperties` entry and calls `action()` for each one whose `test()` returns true:

```java
for (var requestFilter : throttleProperties.getRequest()) {
    if (requestFilter.test(request)) {
        action(requestFilter, request);   // no break/return after first match
    }
}
```

`action()` (lines 70–73) for `THROTTLE` consumes exactly 1 token from the filter's own `Bucket`:

```java
case THROTTLE -> {
    if (!filter.getBucket().tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

Each `RequestProperties` bucket is created in `createBucket()` (lines 63–69) with `capacity = rate` and `refillGreedy(rate, Duration.ofSeconds(1))`, where `rate` is 0–100.

**Root cause:** The loop has no early-exit after the first THROTTLE match. The failed assumption is that each request will match at most one THROTTLE filter. In practice, filters are defined on independent fields (`BLOCK`, `FROM`, `DATA`, `ESTIMATE`, `GAS`, `TO`, `VALUE`) and can overlap freely.

**Exploit flow:**
1. Operator configures N `RequestProperties` entries, all with `ActionType.THROTTLE`, each with a different field filter but overlapping criteria (e.g., Filter A: `BLOCK=latest`, Filter B: `FROM contains 0x`, Filter C: `ESTIMATE=false`).
2. Attacker crafts a single request satisfying all N filter predicates.
3. Each call to `throttle()` consumes 1 token from each of the N per-filter buckets while consuming only 1 token from the global `rateLimitBucket`.
4. The attacker sustains this at the global rate limit (default 500 req/sec), draining all N buckets simultaneously.

**Why existing checks are insufficient:**
- The global `rateLimitBucket` (line 38) limits total request rate but does not prevent one request from touching N per-filter buckets.
- `RequestProperties.test()` (line 50) applies a random sampling check only for non-THROTTLE actions; for `THROTTLE` the random gate is bypassed entirely, so every matching request always consumes a token.
- There is no deduplication, priority ordering, or first-match-wins logic anywhere in the loop.

### Impact Explanation
Legitimate users whose requests match any of the drained THROTTLE filters receive `ThrottleException("Requests per second rate limit exceeded")` even though they are well within their individual filter's intended quota. The attacker achieves a N-fold amplification: one request stream drains N independent rate-limit buckets, effectively multiplying the DoS surface by the number of overlapping THROTTLE filters. Because each bucket refills at `rate` tokens/sec (max 100) and the global limit is 500 req/sec by default, an attacker needs only ⌈rate/500⌉ seconds of sustained traffic to keep all N buckets empty indefinitely.

### Likelihood Explanation
No authentication or privilege is required — the `/api/v1/contracts/call` endpoint is publicly accessible. The attacker only needs to know (or enumerate) which request fields the operator uses as THROTTLE filter criteria, which can be inferred by observing which request shapes trigger throttle responses. The attack is fully repeatable and automatable with a simple HTTP client loop. The precondition (multiple overlapping THROTTLE filters) is a realistic operator configuration when trying to apply fine-grained per-field rate limits.

### Recommendation
Apply a **first-match-wins** (break-after-first-THROTTLE) strategy, or track whether a THROTTLE action has already been applied and skip subsequent THROTTLE entries for the same request:

```java
boolean throttled = false;
for (var requestFilter : throttleProperties.getRequest()) {
    if (requestFilter.test(request)) {
        if (requestFilter.getAction() == ActionType.THROTTLE) {
            if (!throttled) {
                action(requestFilter, request);
                throttled = true;
            }
        } else {
            action(requestFilter, request);
        }
    }
}
```

Alternatively, document that THROTTLE filters must be mutually exclusive and add a startup validation that rejects configurations where multiple THROTTLE entries can match the same request.

### Proof of Concept
**Setup (operator config):**
```yaml
hiero.mirror.web3.throttle:
  requestsPerSecond: 500
  request:
    - action: THROTTLE
      rate: 5
      filters:
        - field: BLOCK
          type: EQUALS
          expression: "latest"
    - action: THROTTLE
      rate: 5
      filters:
        - field: ESTIMATE
          type: EQUALS
          expression: "false"
    - action: THROTTLE
      rate: 5
      filters:
        - field: FROM
          type: CONTAINS
          expression: "0x"
```

**Attack (unprivileged):**
```bash
# Craft a request matching all three THROTTLE filters simultaneously
for i in $(seq 1 6); do
  curl -s -X POST http://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"block":"latest","estimate":false,"from":"0x00000000000000000000000000000000000004e2","to":"0x00000000000000000000000000000000000004e4","gas":50000}' &
done
wait
```

After 5 requests, all three THROTTLE buckets (capacity=5 each) are empty. A legitimate user sending request #6 with `block=latest` (matching only Filter A) receives `ThrottleException` even though they have never sent a request before. The attacker used 5 global tokens to drain 15 filter-bucket tokens across 3 independent buckets.