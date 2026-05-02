### Title
Global Shared Rate-Limit Bucket Enables Unauthenticated DoS Against All Web3 API Users

### Summary
The `rateLimitBucket` in `ThrottleManagerImpl` is a single, process-wide token bucket with no per-IP or per-user partitioning. Any unauthenticated caller can exhaust the entire global request quota by sending requests at or above the configured `requestsPerSecond` rate, causing every subsequent request from every other user to receive `ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED)` until the bucket refills one second later. This is a trivially repeatable, zero-privilege denial-of-service.

### Finding Description
**Exact code path:**

`ThrottleConfiguration.rateLimitBucket()` instantiates a single `Bucket` bean (default capacity = 500 tokens, greedy-refill 500/s):

```java
// ThrottleConfiguration.java:24-32
@Bean(name = RATE_LIMIT_BUCKET)
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond(); // default 500
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)
            .refillGreedy(rateLimit, Duration.ofSeconds(1))
            .build();
    return Bucket.builder().addLimit(limit).build();
}
```

This single bean is injected into `ThrottleManagerImpl` and consumed atomically for every incoming request regardless of caller identity:

```java
// ThrottleManagerImpl.java:37-39
public void throttle(ContractCallRequest request) {
    if (!rateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
    ...
}
```

**Root cause:** There is no per-source-IP, per-account, or per-session bucket. The `ContractCallRequest` carries an optional `from` field (not required when `value == 0`) and no authentication credential. The throttle check is purely against the shared global counter.

**Failed assumption:** The design assumes the aggregate request rate across all callers will stay below `requestsPerSecond`. It provides no mechanism to prevent a single caller from consuming the entire quota.

**Why existing checks are insufficient:**
- The `request[]` filter list (`RequestProperties`) is an opt-in, operator-configured feature that is empty by default and operates on request content fields (`DATA`, `FROM`, `TO`, etc.), not on network identity.
- There is no Spring Security filter, servlet filter, or network-layer guard visible in the application code that enforces per-IP rate limiting for the web3 module.
- The `from` field in `ContractCallRequest` is user-supplied and unverified — it cannot serve as an identity anchor for rate limiting.

### Impact Explanation
An attacker sustaining ≥500 HTTP requests/second to `/api/v1/contracts/call` (or the equivalent JSON-RPC endpoint) will drain the global bucket continuously. Every legitimate user's `eth_call` or `eth_estimateGas` simulation will fail with HTTP 429 for the duration of the attack. dApps and wallets that rely on the mirror node's web3 endpoint for pre-flight contract call simulation (e.g., checking allowances, simulating token transfers, reading on-chain authorization state) will be completely blocked. The attack is stateless and requires no account, no funds, and no prior knowledge of the system.

### Likelihood Explanation
The attack requires only the ability to send unauthenticated HTTP POST requests at ~500 RPS — achievable from a single commodity machine or a small botnet. No exploit code, no cryptographic material, and no privileged access are needed. The attack is continuously repeatable: the bucket refills every second, so the attacker simply needs to maintain the flood. Detection and IP-blocking at the infrastructure layer (load balancer / WAF) is the only external mitigation, but none is enforced by the application itself.

### Recommendation
1. **Per-IP token buckets:** Replace (or supplement) the single global `rateLimitBucket` with a `ConcurrentHashMap<String, Bucket>` keyed on the client IP extracted from `X-Forwarded-For` / `RemoteAddr`. Each IP gets its own bucket sized to `requestsPerSecond / expectedConcurrentClients`.
2. **Global + per-IP two-tier throttle:** Keep the global bucket as a hard ceiling, and add a per-IP bucket (e.g., 50 RPS per IP) so no single source can monopolize the global quota.
3. **Leverage bucket4j's distributed/proxy capabilities** if the service runs behind multiple instances, to avoid per-instance bypass.
4. **Operator-configurable per-IP limit** via `ThrottleProperties` to allow tuning without code changes.

### Proof of Concept
**Preconditions:** Mirror node web3 service running with default config (`requestsPerSecond=500`). No WAF or external IP rate limiter in place.

**Steps:**

```bash
# Attacker terminal: flood the endpoint at >500 RPS from a single IP
# (Apache Bench, wrk, or any HTTP load tool)
wrk -t4 -c200 -d60s -s post.lua http://<mirror-node-host>/api/v1/contracts/call
# post.lua sends a minimal valid ContractCallRequest JSON body

# Legitimate user terminal (concurrent):
curl -X POST http://<mirror-node-host>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000167","gas":50000}'
# Expected result while attack is running:
# HTTP 429 Too Many Requests
# {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

**Result:** The legitimate user's request is rejected for the entire duration of the flood. The attacker requires zero credentials and zero on-chain resources.