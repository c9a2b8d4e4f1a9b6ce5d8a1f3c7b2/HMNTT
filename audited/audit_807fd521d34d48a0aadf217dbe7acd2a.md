### Title
Global Opcode Rate Limit Bucket Allows Single Unauthenticated User to Monopolize Entire Endpoint Capacity (DoS)

### Summary
The `opcodeRateLimitBucket` is a server-wide singleton with a default capacity of 1 token per second and no per-IP or per-user partitioning. Any single unauthenticated user who sends one request per second to the `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint will consume 100% of the global token budget, causing all concurrent and subsequent users within that second to receive HTTP 429. This constitutes a trivially achievable denial-of-service against the entire opcode functionality.

### Finding Description

**Code path:**

`ThrottleProperties.java:29` — default `opcodeRequestsPerSecond = 1`: [1](#0-0) 

`ThrottleConfiguration.java:47-55` — the bucket is a Spring `@Bean` singleton, one shared instance for the entire JVM, with `capacity=1` and `refillGreedy(1, Duration.ofSeconds(1))`: [2](#0-1) 

`ThrottleManagerImpl.java:52-56` — the only check is `opcodeRateLimitBucket.tryConsume(1)` against that global bucket; there is no per-IP, per-session, or per-user sub-bucket: [3](#0-2) 

`OpcodesController.java:59-64` — the controller calls `throttleManager.throttleOpcodeRequest()` with no identity context passed: [4](#0-3) 

**Root cause:** The rate-limit bucket is a global counter, not a per-client counter. The design assumes the 1 RPS ceiling protects the server from load, but it also means the entire capacity is a single shared resource that any one caller can fully occupy. There is no fairness mechanism.

**Failed assumption:** The documentation states the limit is low because "this endpoint is heavy." The implicit assumption is that the limit protects the server. The missing assumption is that the limit must also be fair across callers — which requires per-client isolation.

**Exploit flow:**
1. Attacker discovers the endpoint is enabled (`hiero.mirror.web3.opcode.tracer.enabled=true`).
2. Attacker sends `GET /api/v1/contracts/results/<any_valid_hash>/opcodes` with `Accept-Encoding: gzip` at exactly 1 req/s.
3. Each request consumes the single available token; the bucket refills 1 token/s.
4. Every other user's request within the same second finds 0 tokens and receives HTTP 429 `Requests per second rate limit exceeded`.
5. The attacker sustains this indefinitely with a trivial cron job or `watch` command.

**Why existing checks fail:** The only guard is `opcodeRateLimitBucket.tryConsume(1)` on a global `Bucket` instance. No IP extraction, no `X-Forwarded-For` inspection, no authentication token check, and no per-caller sub-bucket exists anywhere in the call chain. [3](#0-2) 

### Impact Explanation
When the opcode tracer endpoint is enabled, a single unauthenticated attacker can permanently deny all other users access to opcode tracing functionality. Because the endpoint re-executes transactions on the EVM (noted in the controller Javadoc as potentially taking "a significant amount of time"), legitimate users are completely locked out of a resource-intensive debugging/analysis feature. The attacker pays no cost beyond sending one lightweight GET request per second. [5](#0-4) 

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and zero special knowledge beyond knowing the endpoint path (publicly documented in the OpenAPI spec). The attacker needs only a valid transaction hash (also publicly queryable from the mirror node REST API) and a timer firing once per second. The attack is fully repeatable, persistent, and undetectable as abuse since the attacker never exceeds the configured rate limit — they are operating exactly at it. [1](#0-0) 

### Recommendation
Replace the single global bucket with per-client rate limiting keyed on the caller's IP address (or `X-Forwarded-For` behind a proxy). For example, use a `ConcurrentHashMap<String, Bucket>` or Bucket4j's `ProxyManager` backed by a cache (Caffeine/Redis) to maintain one bucket per IP. The global server-side ceiling can remain as a secondary guard, but the primary enforcement must be per-caller. Additionally, consider requiring an API key or authentication token for this endpoint given its computational cost.

### Proof of Concept

**Preconditions:**
- `hiero.mirror.web3.opcode.tracer.enabled=true` is set (operator opt-in).
- A valid transaction hash `<TX_HASH>` is known (obtainable from the public `/api/v1/transactions` endpoint).

**Steps:**

```bash
# Attacker terminal — runs indefinitely at 1 req/s
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node-host>/api/v1/contracts/results/<TX_HASH>/opcodes"
  sleep 1
done
# Output: 200 200 200 200 ... (attacker always succeeds)

# Victim terminal — any concurrent request within the same second
curl -s -H "Accept-Encoding: gzip" \
  "https://<mirror-node-host>/api/v1/contracts/results/<TX_HASH>/opcodes"
# Output: HTTP 429 {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

The attacker's loop consumes the single token each second. Every victim request finds an empty bucket and receives 429 for as long as the attacker loop runs. [2](#0-1)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L47-55)
```java
    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L35-45)
```java
    /**
     * <p>
     * Returns a result containing detailed information for the transaction execution, including all values from the
     * {@code stack}, {@code memory} and {@code storage} and the entire trace of opcodes that were executed during the
     * replay.
     * </p>
     * <p>
     * Note that to provide the output, the transaction needs to be re-executed on the EVM, which may take a significant
     * amount of time to complete if stack and memory information is requested.
     * </p>
     *
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-64)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
```
