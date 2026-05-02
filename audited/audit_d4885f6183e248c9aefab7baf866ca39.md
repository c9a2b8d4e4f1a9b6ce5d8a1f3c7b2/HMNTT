### Title
Global Shared Opcode Rate-Limit Bucket Allows Single Unprivileged User to Monopolize All Opcode Replay Capacity

### Summary
`opcodeRateLimitBucket` is a single application-wide `Bucket` with a default capacity of **1 token per second** and no per-IP or per-user partitioning. Any unauthenticated caller who sends one opcode-replay request per second will continuously drain the sole available token, leaving zero capacity for every other user and producing a complete, sustained denial of the opcode-replay endpoint.

### Finding Description
**Exact code path:**

`ThrottleProperties.java` line 29 sets the default:
```java
private long opcodeRequestsPerSecond = 1;
``` [1](#0-0) 

`ThrottleConfiguration.java` lines 47–55 materialise this as one JVM-singleton `Bucket`:
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
``` [2](#0-1) 

`ThrottleManagerImpl.java` lines 52–56 enforce it with a single global `tryConsume(1)`:
```java
public void throttleOpcodeRequest() {
    if (!opcodeRateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
``` [3](#0-2) 

**Root cause / failed assumption:** The design assumes the opcode-replay endpoint is so rarely used that a global 1 req/s ceiling is acceptable. It fails to account for the fact that a single adversarial caller can permanently occupy that ceiling, because there is no per-source-IP, per-session, or per-user bucket — only one shared counter for the entire service.

**Exploit flow:**
1. Attacker identifies the opcode-replay HTTP endpoint (no authentication required beyond what the general API exposes).
2. Attacker sends exactly 1 opcode-replay request per second in a tight loop.
3. Each request arrives just as the bucket refills its single token; `tryConsume(1)` returns `true` for the attacker.
4. Every concurrent or subsequent request from any other client finds the bucket empty; `tryConsume(1)` returns `false` and a `ThrottleException` is thrown immediately.
5. The attacker sustains this with trivial tooling (e.g., `watch -n 1 curl …`).

**Why existing checks are insufficient:** The only guard is the global `tryConsume` call shown above. There is no IP-keyed bucket map, no per-authenticated-user quota, no request queuing, and no back-pressure mechanism that would distribute the single token fairly across callers. [3](#0-2) 

### Impact Explanation
The opcode-replay endpoint exposes historical Hashgraph transaction execution traces. A successful attack renders this endpoint completely unavailable to all legitimate users for the duration of the attack. Because the default capacity is 1 token/second, the attacker's cost is negligible (one HTTP request per second), while the impact is total: 100 % of the global opcode-replay budget is consumed by one source. This constitutes a targeted denial of historical state access with no collateral damage to other endpoints.

### Likelihood Explanation
No privileges, credentials, or special knowledge are required. The attacker needs only to discover the opcode-replay endpoint path (publicly documented in mirror-node API specs) and issue one request per second. The attack is trivially repeatable, requires no amplification, and is sustainable indefinitely. Any motivated party — a competitor, a researcher stress-testing the API, or a script-kiddie — can execute it.

### Recommendation
1. **Per-IP (or per-authenticated-user) bucketing:** Replace the single global `Bucket` bean with a `CaffeineProxyManager`-backed or `Caffeine`-keyed bucket map, keyed on the client IP (extracted from `X-Forwarded-For` / `RemoteAddr`). Each IP gets its own `opcodeRequestsPerSecond` allowance.
2. **Raise the global ceiling:** Even if per-IP isolation is added, the global default of `1` is so low that any single legitimate user exhausts it. Consider a higher global ceiling (e.g., 10–50) combined with a per-IP sub-limit.
3. **Authentication gate:** Require an API key or JWT for opcode-replay requests; tie the bucket key to the authenticated identity rather than the IP, which is easier to spoof.
4. **Queue / fair-share scheduling:** Instead of immediately rejecting on bucket exhaustion, place requests in a bounded queue and serve them in FIFO order, preventing any single source from starving others.

### Proof of Concept
```bash
# Terminal 1 – attacker (1 req/s, sustains monopoly)
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    "https://<mirror-node-host>/api/v1/contracts/results/<txId>/opcodes"
  sleep 1
done

# Terminal 2 – victim (concurrent legitimate user)
curl -v "https://<mirror-node-host>/api/v1/contracts/results/<txId>/opcodes"
# Expected result while attacker loop is running:
# HTTP 429 / ThrottleException("Requests per second rate limit exceeded")
# Victim receives no opcode trace data for the entire duration of the attack.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L29-29)
```java
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
