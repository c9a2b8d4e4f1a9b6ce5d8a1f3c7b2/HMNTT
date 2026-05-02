### Title
Global Singleton Opcode Rate-Limit Bucket Allows Single Unprivileged User to Permanently Monopolize the Opcode Endpoint

### Summary
`opcodeRateLimitBucket` is a Spring singleton bean shared across all callers with a default capacity of 1 token and a `refillGreedy` refill of 1 token per second. Because there is no per-IP or per-user isolation, a single unauthenticated attacker who sends one request per second in a loop will consume every token as it is refilled, leaving zero tokens for any other user indefinitely.

### Finding Description
**Exact code path:**

`ThrottleConfiguration.java` lines 47–55 construct the bucket:

```java
@Bean(name = OPCODE_RATE_LIMIT_BUCKET)
Bucket opcodeRateLimitBucket() {
    long rateLimit = throttleProperties.getOpcodeRequestsPerSecond(); // default = 1
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)                                       // capacity = 1
            .refillGreedy(rateLimit, Duration.ofSeconds(1))            // +1 token/s, continuous
            .build();
    return Bucket.builder().addLimit(limit).build();                   // global singleton, no sync strategy
}
```

`ThrottleManagerImpl.java` lines 52–56 consume from this single shared instance on every opcode request:

```java
public void throttleOpcodeRequest() {
    if (!opcodeRateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

`OpcodesController.java` lines 59–65 call `throttleOpcodeRequest()` with no authentication and no IP-level guard before it.

**Root cause / failed assumption:** The design assumes the 1-token-per-second global budget will be shared fairly. It is not. `refillGreedy` adds tokens continuously (proportional to elapsed time), so a token is available again approximately 1 second after the previous one was consumed. A single caller who polls at that cadence will always find a token and will never be blocked, while every concurrent caller receives a 429.

**Why existing checks fail:**
- No per-IP or per-session bucket exists anywhere in the throttle stack.
- `rateLimitBucket` (the general RPS bucket, default 500 RPS) is checked first in `throttle()`, but `throttleOpcodeRequest()` is a separate code path that only checks `opcodeRateLimitBucket`.
- There is no authentication requirement on the endpoint (`OpcodesController` is a plain `@RestController` with no security annotation).
- The bucket is not `SYNCHRONIZED` (unlike `gasLimitBucket`), but even if it were, that would only affect thread safety, not per-user fairness.

### Impact Explanation
When the opcode tracer is enabled (`hiero.mirror.web3.opcode.tracer.enabled=true`), a single attacker with a trivial polling script permanently denies all other users access to `GET /api/v1/contracts/results/{transactionIdOrHash}/opcodes`. Every legitimate request receives HTTP 429 for as long as the attacker's loop runs. The endpoint re-executes EVM transactions and is described as "heavy," so the attacker also forces the server to perform expensive computation on every successful poll. Severity matches the stated scope: griefing with no economic damage.

### Likelihood Explanation
Preconditions are minimal: the endpoint must be enabled (operator opt-in), and the attacker needs only an HTTP client. No credentials, no special knowledge, and no precise timing are required — sending one request every ~950 ms is sufficient to reliably consume every refilled token before any other caller can. The attack is trivially scriptable with `curl` or any HTTP library and is indefinitely repeatable.

### Recommendation
Replace the single global bucket with a per-IP (or per-authenticated-identity) bucket map, for example using Bucket4j's `ProxyManager` keyed on the client IP extracted from `HttpServletRequest`. A secondary global cap can remain to bound total server load. Alternatively, enforce authentication on the endpoint and key the bucket on the authenticated principal. At minimum, raise `opcodeRequestsPerSecond` to a value that allows multiple legitimate users to share the budget, and document that the current design provides no fairness guarantee.

### Proof of Concept
```bash
# Attacker terminal — runs indefinitely, consuming every refilled token
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/0x<valid_hash>/opcodes"
  sleep 1
done

# Victim terminal — every request returns 429 while attacker loop is running
curl -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/0x<valid_hash>/opcodes"
# → HTTP 429 {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

The attacker receives HTTP 200 on every iteration; the victim receives HTTP 429 on every attempt.