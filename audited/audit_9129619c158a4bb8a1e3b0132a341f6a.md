### Title
Global Rate-Limit Bucket Starvation via HTTP/2 Multiplexed Stream Burst

### Summary
`rateLimitBucket()` creates a single application-wide Bucket4j token bucket with a burst capacity equal to the full per-second allowance (default 500). Because there is no per-IP or per-connection isolation, a single unprivileged attacker can open one HTTP/2 connection, multiplex 500 concurrent streams simultaneously, drain all 500 tokens in a single network round-trip, and leave zero tokens for every other user for the remainder of that second. The attack is trivially repeatable every second with no authentication or special privilege required.

### Finding Description
**Exact code path:**

`ThrottleConfiguration.rateLimitBucket()` (lines 24–32) constructs one singleton `Bucket` shared across all callers:

```java
// ThrottleConfiguration.java:25-31
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond(); // default 500
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)           // burst capacity = 500
            .refillGreedy(rateLimit, Duration.ofSeconds(1))
            .build();
    return Bucket.builder().addLimit(limit).build(); // no SynchronizationStrategy, no per-IP key
}
```

`ThrottleManagerImpl.throttle()` (line 38) consumes exactly 1 token per request from this single global bucket:

```java
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
}
```

**Root cause:** The bucket is a single JVM-scoped singleton. `capacity(rateLimit)` sets the burst ceiling equal to the full per-second quota. Bucket4j's `refillGreedy` refills tokens continuously, but the initial and maximum token count is `rateLimit` (500). There is no per-source (IP, connection, API key) sub-bucket, no connection-level concurrency cap, and no HTTP/2 stream limit enforced at the application layer.

**Why existing checks fail:** The only guard is `rateLimitBucket.tryConsume(1)` — a single global CAS operation. It correctly rejects request 501 within a second, but it cannot distinguish whether requests 1–500 came from 500 different users or from 500 streams on one TCP connection. The `request[]` filter system (`RequestProperties`, `ThrottleManagerImpl` lines 44–48) is opt-in, content-based, and not configured by default; it provides no IP-level protection.

**Exploit flow:**
1. Attacker opens one HTTP/2 connection to the web3 endpoint.
2. Attacker dispatches 500 `POST /api/v1/contracts/call` requests as concurrent HTTP/2 streams (all in-flight simultaneously).
3. All 500 `tryConsume(1)` calls race against the full bucket; all succeed because capacity = 500.
4. Bucket token count drops to 0.
5. Every subsequent request from any other user within that second receives HTTP 429.
6. After ~1 second the bucket refills; attacker repeats.

### Impact Explanation
All legitimate users are denied service for up to 1 second per attack cycle. Because the attack is repeatable with zero delay between cycles, an attacker can sustain near-100% denial of the web3 RPC endpoint indefinitely from a single persistent connection. The web3 module is the JSON-RPC gateway for EVM contract calls; sustained unavailability prevents dApps and integrations from submitting or simulating transactions, constituting a shutdown of web3 processing capacity without any brute-force or network-flooding requirement.

### Likelihood Explanation
The attack requires no credentials, no special network position, and no prior knowledge beyond the public endpoint URL. HTTP/2 multiplexing is supported by all modern HTTP clients and is trivially scriptable (e.g., `h2load`, `curl --http2`, Python `httpx`). The attacker needs only one outbound TCP connection and 500 concurrent in-flight requests — well within the capability of any commodity machine. The attack is repeatable every second indefinitely and leaves no persistent state to clean up.

### Recommendation
1. **Per-IP token bucket:** Introduce a `LoadingCache<String, Bucket>` keyed on client IP (extracted from `X-Forwarded-For` / `RemoteAddr`) so each source address has its own sub-quota (e.g., ≤ N% of the global limit).
2. **Burst cap separate from refill rate:** Set `capacity` to a fraction of `requestsPerSecond` (e.g., `max(1, requestsPerSecond / 10)`) so no single burst can exhaust the full second's budget.
3. **HTTP/2 stream concurrency limit:** Configure the embedded server (Netty/Tomcat) with `http2.maxConcurrentStreams` to cap simultaneous streams per connection.
4. **Synchronization strategy:** The `rateLimitBucket` currently omits `SynchronizationStrategy` (unlike `gasLimitBucket` which uses `SYNCHRONIZED`); explicitly set a strategy to avoid any ambiguity under concurrent load.

### Proof of Concept
```bash
# Requires h2load (nghttp2) or equivalent HTTP/2 load tool
# Send 500 concurrent requests in a single round-trip from one connection
h2load -n 500 -c 1 -m 500 \
  -H "Content-Type: application/json" \
  --data='{"to":"0x0000000000000000000000000000000000000167","estimate":false}' \
  https://<web3-host>/api/v1/contracts/call

# Expected: all 500 return HTTP 200 (bucket drained)
# Immediately after (within same second):
curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://<web3-host>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"to":"0x0000000000000000000000000000000000000167","estimate":false}'
# Expected: 429 Too Many Requests — legitimate user starved
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
