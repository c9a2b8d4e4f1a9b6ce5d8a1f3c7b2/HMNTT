Looking at the execution order in `OpcodesController.getContractOpcodes()` and the `ThrottleManagerImpl.throttleOpcodeRequest()` implementation, I can trace the exact attack path.

The key sequence in `getContractOpcodes()` is:
1. `validateAcceptEncodingHeader(acceptEncoding)` — passes if header contains "gzip"
2. `throttleManager.throttleOpcodeRequest()` — **unconditionally consumes** 1 token from the global 1-RPS bucket
3. `opcodeService.processOpcodeCall(request)` — fails with 404 if transaction doesn't exist

There is no token restoration on service failure (unlike `gasLimitBucket` which has a `restore()` method). The bucket is a single global instance with no per-IP partitioning.

---

### Title
Global Opcode Rate-Limit Exhaustion via Unauthenticated Requests with Valid-Format Nonexistent Transaction Hashes

### Summary
The `opcodeRateLimitBucket` (1 RPS, globally shared) is consumed unconditionally after the `Accept-Encoding: gzip` header check passes, but before the service call validates whether the transaction actually exists. Any unauthenticated user can trivially satisfy the header check and exhaust the entire per-second budget using valid-format but nonexistent transaction hashes, blocking all legitimate opcode trace requests for the remainder of that second.

### Finding Description
**Code path:**

`OpcodesController.getContractOpcodes()` — `web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java`, lines 59–65:
```java
if (properties.isEnabled()) {
    validateAcceptEncodingHeader(acceptEncoding);   // line 60 — passes if "gzip" present
    throttleManager.throttleOpcodeRequest();        // line 61 — token consumed HERE
    final var request = new OpcodeRequest(...);
    return opcodeService.processOpcodeCall(request); // line 64 — may throw 404
}
```

`ThrottleManagerImpl.throttleOpcodeRequest()` — `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 52–56:
```java
public void throttleOpcodeRequest() {
    if (!opcodeRateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

`ThrottleConfiguration.opcodeRateLimitBucket()` — `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, lines 47–55: the bucket is a **single global instance** with capacity = `opcodeRequestsPerSecond` (default: 1).

**Root cause:** The token is consumed at line 61 before the service call at line 64. If the service call throws (e.g., `EntityNotFoundException` for a nonexistent transaction), the token is **not restored**. There is no `restore()` equivalent for the opcode bucket (contrast with `gasLimitBucket` which has `ThrottleManager.restore(long gas)`). The bucket is global — not partitioned by IP, session, or identity.

**Why the header check is insufficient:** `validateAcceptEncodingHeader` only checks `acceptEncodingHeader.toLowerCase().contains("gzip")`. Any HTTP client can trivially set `Accept-Encoding: gzip`. This check was designed to enforce compression for large responses, not to gate access to the rate-limit token.

### Impact Explanation
The default `opcodeRequestsPerSecond` is 1 (documented in `docs/configuration.md` line 723 and enforced in `ThrottleProperties.java` line 29). A single attacker sending one request per second with `Accept-Encoding: gzip` and a valid-format (but nonexistent) 64-character hex transaction hash will consume the entire global budget. Every legitimate opcode trace request within that second receives HTTP 429. Since the bucket refills greedily at 1 token/second, sustained attack at 1 req/s completely starves all other users. The endpoint is intended for debugging/auditing EVM transactions; its unavailability blocks all such forensic activity.

### Likelihood Explanation
No privileges, authentication, or special knowledge are required. The attacker needs only: (1) a valid-format hex string (e.g., 64 `0`s), and (2) the `Accept-Encoding: gzip` header. Both are trivially supplied by any HTTP client (`curl`, Python `requests`, etc.). The attack is repeatable indefinitely at 1 req/s with negligible cost to the attacker.

### Recommendation
1. **Restore the token on failed service calls**: Wrap `opcodeService.processOpcodeCall(request)` in a try/catch and return the consumed token to the bucket on non-throttle exceptions (similar to how `gasLimitBucket` uses `restore()`).
2. **Move throttle after input validation**: Validate that the `transactionIdOrHash` resolves to an existing record before consuming the rate-limit token, or at minimum perform a lightweight existence check first.
3. **Per-IP rate limiting**: Partition the opcode rate limit by client IP (e.g., using a `ConcurrentHashMap<String, Bucket>`) so one client cannot exhaust the global budget.
4. **Require authentication**: Gate the opcodes endpoint behind an API key or similar credential, since it is already a privileged/heavy debugging endpoint.

### Proof of Concept
```bash
# Exhaust the global 1 RPS opcode budget with a nonexistent transaction hash
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/0000000000000000000000000000000000000000000000000000000000000000/opcodes"
  sleep 1
done
# Legitimate user in parallel:
curl -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/<real-tx-hash>/opcodes"
# → HTTP 429 Too Many Requests (rate limit exhausted by attacker)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L75-86)
```java
    private void validateAcceptEncodingHeader(String acceptEncodingHeader) {
        if (acceptEncodingHeader == null || !acceptEncodingHeader.toLowerCase().contains("gzip")) {
            throw HttpClientErrorException.create(
                    MISSING_GZIP_HEADER_MESSAGE,
                    HttpStatus.NOT_ACCEPTABLE,
                    HttpStatus.NOT_ACCEPTABLE.getReasonPhrase(),
                    null, // headers
                    null, // body
                    null // charset
                    );
        }
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
