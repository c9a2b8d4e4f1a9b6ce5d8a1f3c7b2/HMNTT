### Title
Global Single-Bucket Rate Limiter Allows Single Unprivileged User to DoS the Opcode Tracing Endpoint

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint enforces rate limiting via a single application-wide `opcodeRateLimitBucket` with a default capacity of 1 token per second. Because the bucket is global and not partitioned per client IP or identity, a single unauthenticated attacker sending requests at 1 RPS continuously consumes every available token, leaving zero tokens for all other users and causing a complete denial of service for the opcode tracing endpoint.

### Finding Description
**Code path:**

In `OpcodesController.java`, `getContractOpcodes()` calls `throttleManager.throttleOpcodeRequest()` unconditionally before processing: [1](#0-0) 

`ThrottleManagerImpl.throttleOpcodeRequest()` performs a single `tryConsume(1)` against the shared global bucket: [2](#0-1) 

The `opcodeRateLimitBucket` bean is a Spring singleton (one instance for the entire application), configured with `capacity = opcodeRequestsPerSecond` and a greedy refill of the same rate per second: [3](#0-2) 

The default value of `opcodeRequestsPerSecond` is **1**: [4](#0-3) 

**Root cause:** The bucket is a single global counter with no per-IP, per-session, or per-identity partitioning. The design assumes the 1 RPS limit is shared fairly across all callers, but there is no enforcement mechanism to prevent one caller from consuming all tokens.

**Exploit flow:**
1. Attacker identifies any valid historical transaction hash for a computationally expensive contract call.
2. Attacker sends `GET /api/v1/contracts/results/{hash}/opcodes?stack=true&memory=true&storage=true` with `Accept-Encoding: gzip` at exactly 1 RPS in a loop.
3. Each request consumes the single available token the instant it refills.
4. All concurrent legitimate users receive HTTP 429 (`ThrottleException: "Requests per second rate limit exceeded"`).
5. The attacker's own requests succeed (or they can even send slightly above 1 RPS, accepting their own occasional 429s, while still starving all other users).

**Why existing checks fail:** The only check is `opcodeRateLimitBucket.tryConsume(1)` — a global boolean gate. There is no per-client bucket, no IP-based sub-limit, no queue fairness, and no authentication requirement. The `gasLimitBucket` uses `SynchronizationStrategy.SYNCHRONIZED` for thread safety but the `opcodeRateLimitBucket` does not even have that, though the primary issue is the global-only design. [5](#0-4) 

### Impact Explanation
Any unauthenticated user can fully monopolize the opcode tracing endpoint for the entire service. All other users — including legitimate developers, auditors, and monitoring tools — receive HTTP 429 for the duration of the attack. Since the endpoint re-executes EVM transactions (noted in the Javadoc as potentially taking "a significant amount of time"), even a single successful request per second by the attacker keeps the server busy while blocking all others. This is a complete availability loss for the `/opcodes` endpoint.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only a valid transaction hash (publicly available on-chain). The attacker needs to sustain only 1 HTTP request per second — trivially achievable with `curl` in a shell loop or any scripting language. The attack is repeatable indefinitely, requires no special tooling, and is not detectable or blockable by the current application-layer controls.

### Recommendation
Replace the single global bucket with per-client rate limiting, keyed on the client IP address (e.g., from `X-Forwarded-For` or `HttpServletRequest.getRemoteAddr()`). Each client IP should have its own bucket (e.g., using a `ConcurrentHashMap<String, Bucket>` or Bucket4j's distributed/proxy support). The global bucket can remain as a secondary server-protection ceiling, but per-client isolation must be added to prevent monopolization. Additionally, consider requiring authentication for this endpoint given its computational cost.

### Proof of Concept
```bash
# Attacker terminal: consume all tokens continuously
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/<valid_tx_hash>/opcodes?stack=true&memory=true&storage=true"
  sleep 0.9  # slightly under 1s to always win the token race
done

# Victim terminal (concurrent): all requests return 429
curl -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/<valid_tx_hash>/opcodes"
# Response: HTTP 429 {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

The victim receives HTTP 429 for as long as the attacker loop runs, with no recourse at the application layer.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-65)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L34-44)
```java
    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```
