### Title
Global Rate-Limit Bucket Exhaustion via Unauthenticated Request Flooding on `POST /api/v1/contracts/call`

### Summary
The `rateLimitBucket` in `ThrottleManagerImpl` is a single application-wide token bucket (default 500 tokens/second) shared across all callers with no per-IP or per-client partitioning. Any unauthenticated attacker who sends more than 500 requests per second exhausts the global bucket, causing every subsequent request from every legitimate caller to receive HTTP 429 until the bucket refills. No per-IP rate limiting exists at any layer of the application code.

### Finding Description
**Exact code path:**

`ContractController.call()` (line 40) delegates unconditionally to `ThrottleManagerImpl.throttle()`:
```
throttleManager.throttle(request);   // ContractController.java:40
```
Inside `ThrottleManagerImpl.throttle()` (lines 38–39):
```java
if (!rateLimitBucket.tryConsume(1)) {
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
}
```
`rateLimitBucket` is a single Spring `@Bean` (singleton) constructed in `ThrottleConfiguration.rateLimitBucket()` (lines 24–32):
```java
Bucket.builder().addLimit(limit).build();   // no per-IP partitioning
```
Default capacity is `requestsPerSecond = 500` (`ThrottleProperties.java:35`).

**Root cause:** The bucket is a single in-process, in-memory counter. Every incoming HTTP request, regardless of source IP, consumes one token from the same pool. There is no per-client, per-IP, or per-session bucket.

**Why existing checks fail:**
- `RequestFilter` fields (`DATA`, `GAS`, `TO`, `BLOCK`, `VALUE`) — none is source IP; there is no `FROM_IP` filter field.
- GCP backend policy `maxRatePerEndpoint: 250` (`values.yaml:56`) limits requests routed *to a pod*, not requests *from a client*. Combined with `sessionAffinity: CLIENT_IP` (`values.yaml:58`), the attacker's requests are pinned to one pod, making exhaustion of that pod's bucket even easier.
- Traefik middleware (`values.yaml:157–160`) only configures retry, not rate limiting.
- HPA is disabled by default (`values.yaml:98`).
- No Spring Security filter, no servlet filter, and no WAF rule enforces per-IP limits anywhere in the codebase.

### Impact Explanation
An attacker who sustains ≥501 requests/second against `POST /api/v1/contracts/call` drains the global 500-token bucket. All legitimate callers — regardless of their own request rate — receive HTTP 429 `Too Many Requests` for the remainder of that second. Because the bucket refills greedily every second and the attacker can immediately re-exhaust it, the endpoint is effectively unavailable for the duration of the attack. This is a complete denial-of-service of the contract simulation API, blocking dApps, wallets, and tooling that depend on `eth_call` / `eth_estimateGas` semantics exposed by this endpoint.

### Likelihood Explanation
The attack requires no authentication, no special knowledge, and no privileged access — only the ability to send HTTP POST requests. 501 requests/second is trivially achievable from a single modern machine (e.g., `wrk`, `hey`, `ab`, or a simple async HTTP client). A distributed source (even a small botnet of 5–10 machines at 100 RPS each) achieves the same result. The attack is repeatable indefinitely, costs the attacker almost nothing (requests are rejected quickly after bucket exhaustion), and requires no state. The public nature of the endpoint (CORS `allowedOrigins("*")`, no authentication) makes it reachable by anyone.

### Recommendation
1. **Per-IP rate limiting at the application layer**: Replace the single global `Bucket` with a `ConcurrentHashMap<String, Bucket>` keyed on the resolved client IP (respecting `X-Forwarded-For` via `ForwardedHeaderFilter`), so each IP has its own token budget.
2. **Ingress-level rate limiting**: Add a Traefik `RateLimit` middleware (e.g., `average: 50`, `burst: 100` per source IP) to the existing middleware chain in `values.yaml`.
3. **GCP Cloud Armor / WAF**: Enable per-IP rate-based ban rules on the GCP Gateway to block IPs exceeding a threshold before traffic reaches the pod.
4. **Retain the global bucket** as a secondary backstop against distributed floods, but it must not be the only control.

### Proof of Concept
**Preconditions:** Network access to the deployed endpoint; no credentials required.

**Steps:**
```bash
# Install 'hey' (https://github.com/rakyll/hey)
# Send 600 concurrent requests/second for 5 seconds
hey -n 3000 -c 600 -q 600 -m POST \
  -H "Content-Type: application/json" \
  -d '{"to":"0x0000000000000000000000000000000000000167","gas":50000}' \
  https://<target>/api/v1/contracts/call
```

**Expected result:**
- First ~500 requests in second 1 return HTTP 200.
- Requests 501–3000 return HTTP 429 `{"_status":{"messages":[{"message":"Too Many Requests","detail":"Requests per second rate limit exceeded"}]}}`.
- Any legitimate user sending a single request during the same window also receives HTTP 429.

**Verification of global impact (second terminal):**
```bash
# While the flood is running, send a single legitimate request from a different IP
curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d '{"to":"0x0000000000000000000000000000000000000167","gas":50000}' \
  https://<target>/api/v1/contracts/call
# Returns: 429
```