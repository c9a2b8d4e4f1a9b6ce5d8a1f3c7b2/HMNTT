### Title
Global-Only Rate Limit Bucket Enables Distributed Denial-of-Service via Botnet/Proxy Exhaustion

### Summary
`ThrottleConfiguration.rateLimitBucket()` creates a single application-wide Bucket4j token bucket shared across all source IPs, with no per-IP tracking at any layer. An unprivileged attacker controlling as few as 500 distributed IPs — each sending only 1 request/second — can collectively exhaust the entire 500 RPS global budget, causing all legitimate users to receive HTTP 429 responses while every individual attacker IP remains below any detectable threshold.

### Finding Description

**Exact code path:**

`ThrottleConfiguration.rateLimitBucket()` (lines 24–32) instantiates one `Bucket` for the entire JVM process:

```java
// ThrottleConfiguration.java:25-31
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond(); // default 500
    final var limit = Bandwidth.builder()
            .capacity(rateLimit)
            .refillGreedy(rateLimit, Duration.ofSeconds(1))
            .build();
    return Bucket.builder().addLimit(limit).build();
}
```

`ThrottleManagerImpl.throttle()` (lines 37–42) consumes one token from this single shared bucket for every incoming request, with no reference to the caller's IP address:

```java
// ThrottleManagerImpl.java:37-42
public void throttle(ContractCallRequest request) {
    if (!rateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
        throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
    }
    ...
}
```

**Root cause:** The bucket is keyed on nothing — there is no `Map<InetAddress, Bucket>`, no `X-Forwarded-For` extraction, no `remoteAddr` inspection anywhere in the throttle stack. The failed assumption is that a global ceiling is sufficient to prevent abuse; it is not when the attacker is distributed.

**Infrastructure layer — no compensating control for web3:**

The Helm chart for `hedera-mirror-web3` defines only a `retry` middleware:

```yaml
# charts/hedera-mirror-web3/values.yaml:157-160
middleware:
  - retry:
      attempts: 3
      initialInterval: 100ms
```

Contrast this with `hedera-mirror-rosetta/values.yaml` (lines 149–163) and `hedera-mirror-graphql/values.yaml` (lines 135–146), which both configure Traefik `inFlightReq` with `ipStrategy` and (for rosetta) `rateLimit` with `requestHost: true`. The web3 service has neither.

The GCP gateway entry (`maxRatePerEndpoint: 250`, `sessionAffinity: CLIENT_IP`) is a backend-pod throughput cap and a routing-stickiness hint respectively — neither enforces a per-client-IP request rate limit.

**No per-IP check exists anywhere in the Java codebase** — confirmed by grep across all `.java` files: `X-Forwarded-For`, `remoteAddr`, `perIp`, and `ipStrategy` return zero hits in the web3 throttle path.

### Impact Explanation

When the global 500-token bucket is drained, `tryConsume(1)` returns `false` for every subsequent request regardless of source, and the controller returns HTTP 429 to all callers — including legitimate users. Because the attacker's per-IP rate is indistinguishable from normal traffic (1 req/s per node), automated IP-based blocking at a WAF or CDN layer will not trigger. The EVM contract-call endpoint (`/api/v1/contracts/call`) is the highest-value target: each request may trigger expensive database queries and EVM simulation, so even a sustained 500 RPS attack causes both rate-limit exhaustion and backend resource pressure simultaneously.

### Likelihood Explanation

Botnets and residential proxy networks capable of 500+ distinct source IPs are commercially available and inexpensive. The attacker needs no credentials, no API key, and no knowledge of the application beyond the public endpoint. The attack is trivially repeatable: the global bucket refills every second, so the attacker simply maintains a steady 500 req/s aggregate to keep the bucket permanently empty. Detection is difficult because no single IP exceeds 1–2 req/s.

### Recommendation

1. **Per-IP token buckets at the application layer:** Replace the single `Bucket` bean with a `ConcurrentHashMap<String, Bucket>` keyed on the client IP (extracted from `X-Forwarded-For` or `HttpServletRequest.getRemoteAddr()`), with a per-IP limit (e.g., 10–20 RPS) enforced before the global bucket check.

2. **Add Traefik per-IP middleware for web3** (matching what rosetta/graphql already have):
   ```yaml
   middleware:
     - inFlightReq:
         amount: 5
         sourceCriterion:
           ipStrategy:
             depth: 1
     - rateLimit:
         average: 20
         sourceCriterion:
           requestHost: true
   ```

3. **Evict stale per-IP buckets** using a `Caffeine` cache with `expireAfterAccess` to prevent memory exhaustion from IP churn.

### Proof of Concept

**Preconditions:** Public access to `/api/v1/contracts/call`; attacker controls ≥500 distinct source IPs (e.g., residential proxy pool).

**Steps:**

```bash
# From 500 distinct proxy IPs, each running:
while true; do
  curl -s -o /dev/null -X POST https://<target>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"0x","to":"0x0000000000000000000000000000000000000167","gas":21000}'
  sleep 1
done
```

**Trigger:** Aggregate across all 500 IPs = 500 req/s → global bucket permanently empty.

**Result:** All subsequent requests from any IP (including legitimate users) receive:
```
HTTP/1.1 429 Too Many Requests
{"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

Each individual attacker IP sends only 1 req/s and is never individually throttled or blocked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** charts/hedera-mirror-web3/values.yaml (L157-161)
```yaml
middleware:
  - retry:
      attempts: 3
      initialInterval: 100ms

```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
