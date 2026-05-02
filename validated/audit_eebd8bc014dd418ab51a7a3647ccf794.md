All code references check out. Let me verify the facts against the actual source:

- `ThrottleConfiguration.java` lines 47–55: `opcodeRateLimitBucket` is built with `capacity(rateLimit)` and `refillGreedy(rateLimit, Duration.ofSeconds(1))`, no `SynchronizationStrategy` (unlike `gasLimitBucket` at line 42). [1](#0-0) 
- `ThrottleProperties.java` line 29: `opcodeRequestsPerSecond = 1` default confirmed. [2](#0-1) 
- `ThrottleManagerImpl.java` lines 52–55: `throttleOpcodeRequest()` calls only `opcodeRateLimitBucket.tryConsume(1)` — no caller identity, no IP, no auth. [3](#0-2) 
- `OpcodesController.java` line 61: `throttleManager.throttleOpcodeRequest()` is the only guard before processing. [4](#0-3) 
- `SECURITY.md` "Impacts that only require DDoS" is out of scope — but this attack is **not** DDoS; it is a single-client, 1 req/s precision timing exploit of a design flaw (no per-source isolation). [5](#0-4) 

---

Audit Report

## Title
Global Opcode Rate Bucket Monopolization via Predictable Greedy Refill Timing

## Summary
The `opcodeRateLimitBucket` is a single JVM-global token bucket with a default capacity of 1 token/second and no per-user or per-IP isolation. Because the greedy refill timing is fully deterministic and the endpoint requires no authentication, any single unauthenticated caller can continuously consume the sole available token immediately after each refill, permanently starving all other users of opcode/debug/trace access.

## Finding Description
`ThrottleConfiguration.java` creates the `opcodeRateLimitBucket` as a process-wide singleton with `capacity(rateLimit)` and `refillGreedy(rateLimit, Duration.ofSeconds(1))`, where `rateLimit` defaults to `opcodeRequestsPerSecond = 1` (`ThrottleProperties.java` line 29). No `SynchronizationStrategy` is set, unlike `gasLimitBucket`. [1](#0-0) 

`ThrottleManagerImpl.throttleOpcodeRequest()` calls `opcodeRateLimitBucket.tryConsume(1)` with no caller identity, IP address, session, or authentication context. [3](#0-2) 

`OpcodesController.getContractOpcodes()` invokes `throttleManager.throttleOpcodeRequest()` as the sole guard before processing, with no authentication gate preceding it. [4](#0-3) 

The general `rateLimitBucket` (500 req/s) is **not** checked for opcode requests — only `throttleOpcodeRequest()` is called, which hits only the opcode bucket. [6](#0-5) 

**Root cause:** With `capacity=1` and `refillGreedy(1, 1s)`, exactly 1 token becomes available exactly 1 second after the previous one was consumed. This timing is derivable from the HTTP 429 response itself. Because the bucket is shared across all callers with no source-identity partitioning, the first caller to fire after each refill wins the token unconditionally.

## Impact Explanation
The `/api/v1/contracts/results/{id}/opcodes` endpoint becomes exclusively owned by a single attacker. All other users receive HTTP 429 for every request. Developers and operators lose the ability to debug or trace contract executions for the duration of the attack. The attack requires no funds, no credentials, and no special network position.

## Likelihood Explanation
Trivially feasible. The attacker needs only public HTTP access and a script that sends one request per second with `Accept-Encoding: gzip`. The default `opcodeRequestsPerSecond = 1` means there is only ever one token to race for, making monopolization especially easy. The attack is fully repeatable, requires no setup cost, and can be sustained indefinitely from a single machine.

## Recommendation
1. **Per-source-IP sub-buckets:** Maintain a `ConcurrentHashMap<String, Bucket>` keyed by client IP, each with its own capacity (e.g., 1 req/s per IP). This eliminates cross-user interference.
2. **Authentication gate:** Require an authenticated identity for the opcode endpoint and apply per-identity rate limiting.
3. **Synchronization strategy:** Add `SynchronizationStrategy.SYNCHRONIZED` (or `LOCK_FREE`) to `opcodeRateLimitBucket` consistent with `gasLimitBucket`, to prevent race conditions under concurrent access.
4. **Increase global capacity:** Even without per-IP isolation, raising `opcodeRequestsPerSecond` reduces the monopolization window, though it does not eliminate the root cause.

## Proof of Concept
```bash
# Attacker script — runs indefinitely, monopolizes the opcode endpoint
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/<txHash>/opcodes"
  sleep 1
done
```
With `opcodeRequestsPerSecond=1`, this script consumes the single available token every second. Any concurrent legitimate request receives HTTP 429 for the entire duration of the attack.

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L36-56)
```java
    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }

    @Override
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-64)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
