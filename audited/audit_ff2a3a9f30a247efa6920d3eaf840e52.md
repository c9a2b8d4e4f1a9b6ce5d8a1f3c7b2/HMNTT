### Title
Global Shared Rate-Limit Bucket Allows Unauthenticated DoS via Token Exhaustion

### Summary
`ThrottleConfiguration.rateLimitBucket()` creates a single application-wide `Bucket` with a fixed capacity of 500 tokens (default `requestsPerSecond`). Every incoming request, regardless of source IP or identity, consumes from this one shared pool. An unprivileged attacker controlling multiple connections or IPs can saturate the entire 500 RPS budget, causing all subsequent legitimate requests to receive a throttle error until the bucket refills.

### Finding Description
**Code path:**
- `ThrottleConfiguration.java` lines 24–32: a single `@Bean` `Bucket` is constructed with `capacity(rateLimit)` and `refillGreedy(rateLimit, Duration.ofSeconds(1))` — one instance for the entire JVM.
- `ThrottleManagerImpl.java` line 38: every call to `throttle()` does `rateLimitBucket.tryConsume(1)` against that same singleton bucket. No caller identity (IP, token, session) is inspected before consuming.

**Root cause:** The bucket is a Spring singleton with no per-source partitioning. The `RequestProperties` filter system (`FilterField` enum) supports filtering on `BLOCK`, `GAS`, `TO`, `DATA`, `VALUE` — there is no `IP` or `CALLER` field. There is no middleware layer that creates per-IP sub-buckets before the global check.

**Exploit flow:**
1. Attacker opens N concurrent HTTP connections (or uses N IPs via proxies/botnet).
2. Each connection fires requests at the web3 endpoint as fast as possible.
3. Collectively they drain all 500 tokens within the first second.
4. `tryConsume(1)` returns `false` for every subsequent request in that second window.
5. `ThrottleManagerImpl` throws `ThrottleException("Requests per second rate limit exceeded")` for all legitimate callers until the bucket refills at the next 1-second boundary.

**Why existing checks are insufficient:**
- The `RequestProperties` REJECT/THROTTLE rules are content-based (payload fields), not identity-based; they cannot isolate a flooding source IP.
- There is no IP allowlist, connection-level limit, or per-client sub-bucket anywhere in the throttle stack.
- The `gasLimitBucket` is a separate concern and does not protect the RPS budget.

### Impact Explanation
Any unauthenticated caller can render the web3 JSON-RPC endpoint completely unresponsive to all other users for sustained periods. Legitimate users querying contract state or transaction history receive HTTP 429-equivalent errors. Because the bucket refills greedily every second, the attacker only needs to maintain ≥500 req/s to keep the bucket perpetually empty. This is a full availability denial for the web3 service.

### Likelihood Explanation
The precondition is zero: no account, no authentication, no special knowledge. A single machine with a modest HTTP load tool (e.g., `wrk`, `hey`, `ab`) can easily sustain 500+ req/s. Using multiple IPs is not even required — a single IP with pipelining or concurrent connections suffices. The attack is trivially repeatable and automatable.

### Recommendation
Replace the single global bucket with a per-source-IP bucket map (e.g., using Bucket4j's `ProxyManager` backed by a `CaffeineProxyManager` or similar). Each unique client IP gets its own bucket capped at a per-IP limit (e.g., 10–50 RPS), while the global bucket acts as a secondary ceiling. Extract the client IP in a servlet filter or Spring `HandlerInterceptor` before `ThrottleManagerImpl.throttle()` is called, and route the `tryConsume` call to the per-IP bucket. Additionally, consider adding an `IP` field to `RequestFilter.FilterField` to allow operator-configured IP-based REJECT rules.

### Proof of Concept
```bash
# Single attacker machine, no special privileges needed
# Install: apt install wrk  (or use hey/ab)

# Target: web3 JSON-RPC endpoint (eth_call or similar)
wrk -t 10 -c 100 -d 30s \
  -s post.lua \
  http://<mirror-node-host>:8545/api/v1/contracts/call

# post.lua:
# wrk.method = "POST"
# wrk.body   = '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x...","data":"0x"},"latest"],"id":1}'
# wrk.headers["Content-Type"] = "application/json"

# Expected result within ~1 second:
# All responses from legitimate concurrent clients return:
#   HTTP 429 / {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
# Attacker sustains this by keeping throughput >= 500 req/s.
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
