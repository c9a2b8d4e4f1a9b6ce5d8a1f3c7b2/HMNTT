### Title
Global Opcode Rate-Limit Bucket Starvation via Single-Token Monopolization

### Summary
The `opcodeRateLimitBucket` is a single, globally-shared bucket with a default capacity of 1 token and a 1-token-per-second greedy refill. Because there is no per-client or per-IP isolation, any unauthenticated external caller can continuously consume the sole token as soon as it refills, permanently starving all other users from the opcode endpoint with as little as one HTTP request per second.

### Finding Description
**Code locations:**

- `ThrottleProperties.java` line 29: default `opcodeRequestsPerSecond = 1`
- `ThrottleConfiguration.java` lines 47–55: bucket built as `capacity(1).refillGreedy(1, Duration.ofSeconds(1))` — one global singleton bean
- `ThrottleManagerImpl.java` lines 52–55: `throttleOpcodeRequest()` calls `opcodeRateLimitBucket.tryConsume(1)` on that single shared bucket with no caller identity
- `OpcodesController.java` lines 52–68: endpoint is publicly reachable; only guard is the `Accept-Encoding: gzip` header check before `throttleManager.throttleOpcodeRequest()` is called

**Root cause:** The bucket is a process-wide singleton. `tryConsume(1)` is called identically for every caller regardless of source IP, session, or identity. With capacity=1, the entire global allowance is one token. There is no fairness queue, no per-client sub-bucket, and no back-pressure that would prevent one caller from repeatedly winning the refill race.

**Exploit flow:**

1. Attacker sends `GET /api/v1/contracts/results/{any-valid-id}/opcodes` with `Accept-Encoding: gzip` — consumes the single token.
2. Attacker loops with a ~900 ms sleep between requests. Because `refillGreedy` adds the token back continuously after 1 second, the attacker's next request arrives just after the refill and consumes it again.
3. Every legitimate request that arrives between the attacker's polls finds the bucket empty and receives HTTP 429.
4. No authentication, no IP check, no CAPTCHA, and no per-user quota exist to prevent this.

**Why existing checks are insufficient:**

- `tryConsume(1)` is a non-blocking, first-come-first-served check on a shared counter — it has no notion of fairness or caller identity.
- The `Accept-Encoding: gzip` header requirement is trivially satisfied by any HTTP client.
- There is no IP-based rate limiter, no session token, and no authentication layer in front of this endpoint in the web3 module. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
The opcode endpoint replays full EVM transactions with stack/memory/storage tracing — it is a high-value debugging path. With the global bucket at capacity=1, a single attacker running a trivial polling loop at 1 req/s causes a 100% denial-of-service on this endpoint for all other users. No legitimate opcode request can succeed while the attack is active. Because the attacker only needs to sustain 1 request/second, the cost of the attack is negligible while the impact is total.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and zero specialized knowledge beyond knowing the endpoint URL and the `Accept-Encoding: gzip` requirement (visible in any API documentation or network trace). A single `curl` loop or a trivial script is sufficient. The attack is fully repeatable and can be sustained indefinitely at minimal cost. Any motivated party — competitor, researcher, or malicious actor — can execute it immediately upon discovering the endpoint.

### Recommendation
1. **Per-client rate limiting**: Replace or augment the global bucket with a per-IP (or per-authenticated-user) bucket, e.g., using a `ConcurrentHashMap<String, Bucket>` keyed on the client IP extracted from `HttpServletRequest`.
2. **Increase capacity**: Even raising `opcodeRequestsPerSecond` to a value > 1 reduces the monopolization window, though it does not eliminate the root cause.
3. **Authentication gate**: Require an API key or session token for the opcode endpoint so that abusive callers can be identified and blocked.
4. **Fairness queue**: Use a token-bucket variant with per-caller fairness, or place a reverse-proxy (e.g., nginx `limit_req` with `$binary_remote_addr`) in front of the endpoint.

### Proof of Concept
```bash
# Attacker terminal — runs indefinitely at ~1 req/s
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node-host>/api/v1/contracts/results/0.0.1234-1234567890-000000000/opcodes"
  sleep 0.9
done

# Victim terminal — every request returns 429 while attacker loop is running
curl -v -H "Accept-Encoding: gzip" \
  "https://<mirror-node-host>/api/v1/contracts/results/0.0.1234-1234567890-000000000/opcodes"
# Expected: HTTP 429 Too Many Requests
# {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

The attacker's loop consumes the single refilled token on every cycle. The victim's request always finds the bucket empty and is rejected with HTTP 429.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-55)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-65)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```
