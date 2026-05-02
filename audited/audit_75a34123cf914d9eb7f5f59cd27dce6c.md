### Title
Unbounded Response Buffering via `ShallowEtagHeaderFilter` on All `/api/*` Endpoints Enables Unauthenticated Resource-Exhaustion DoS

### Summary
`etagFilter()` in `RestJavaConfiguration` registers Spring's `ShallowEtagHeaderFilter` across every endpoint matching `/api/*` with no concurrency or rate-limiting guard in the `rest-java` service. `ShallowEtagHeaderFilter` wraps every response in a `ContentCachingResponseWrapper`, buffering the entire serialized response body in JVM heap memory before computing the ETag hash. An unprivileged attacker who floods expensive list endpoints with concurrent requests forces proportional heap allocation per request, exhausting JVM memory and causing GC stalls or OOM that degrade or halt all API responses, including transaction-related ones.

### Finding Description

**Exact code path:**

`rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java`, lines 42–46:

```java
@Bean
FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
    final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
    filterRegistrationBean.addUrlPatterns("/api/*");
    return filterRegistrationBean;
}
```

`ShallowEtagHeaderFilter` (Spring Framework) wraps the `HttpServletResponse` in a `ContentCachingResponseWrapper`. The entire response body is written into an in-memory byte array before the filter computes an MD5 digest for the `ETag` header and flushes the buffer to the real output stream. This doubles the effective per-request heap cost for every response served under `/api/*`.

**Root cause:** The filter is applied unconditionally to all endpoints under `/api/*` with no maximum response-size guard, no concurrency limit, and no per-IP or global rate limit within the `rest-java` service. The `rest-java` config directory contains only `LoggingFilter` and `MetricsFilter` alongside `ShallowEtagHeaderFilter`; no throttle bean analogous to the `web3` module's `ThrottleConfiguration`/`ThrottleManagerImpl` exists here.

**Failed assumption:** The design assumes that upstream infrastructure (load balancer, ingress) will absorb abusive traffic before it reaches the JVM. No such assumption is enforced in code, and the filter itself provides no escape hatch.

**Expensive endpoints available to an attacker (all under `/api/*`):**
- `GET /api/v1/network/nodes` — returns paginated `NetworkNodesResponse` with full node detail
- `GET /api/v1/accounts/{id}/allowances/nfts` — paginated NFT allowance list
- `GET /api/v1/accounts/{id}/airdrops/outstanding` / `pending` — paginated token airdrop lists
- `GET /api/v1/network/fees` — deserializes and maps full fee schedule file

Each of these triggers a DB query, full object serialization, and then full in-memory buffering by the ETag filter before any byte reaches the client.

### Impact Explanation

An attacker sending N concurrent requests to a large-response endpoint causes N × (response_size) bytes of live heap allocation simultaneously. For a `NetworkNodesResponse` with the default page size, each response can be tens of KB. At 500–1000 concurrent connections (trivially achievable with `wrk` or `ab`), this can consume hundreds of MB to several GB of heap, triggering continuous full GC cycles. During GC stop-the-world pauses, all threads serving transaction-related API responses are suspended, producing the "temporary freeze" described. Sustained pressure causes OOM and JVM crash, taking the entire `rest-java` service offline. Because the filter covers `/api/*`, no endpoint is exempt.

### Likelihood Explanation

No authentication, API key, or proof-of-work is required. Any internet-accessible deployment is reachable. The attack is repeatable, scriptable, and requires only a standard HTTP client. The absence of application-level rate limiting in `rest-java` (confirmed by reviewing all config-layer beans) means the only mitigation is external infrastructure, which is not guaranteed in all deployment configurations. Likelihood is **high** for any publicly exposed instance.

### Recommendation

1. **Add a response-size cap to `ShallowEtagHeaderFilter`**: Subclass `ShallowEtagHeaderFilter`, override `isEligibleForEtag()`, and return `false` when the response `Content-Length` exceeds a configured threshold (e.g., 64 KB), preventing buffering of large payloads.
2. **Restrict the URL pattern**: Apply the ETag filter only to endpoints where conditional GET is meaningful and responses are small/stable (e.g., single-resource lookups), not broad list endpoints.
3. **Add application-level rate limiting to `rest-java`**: Mirror the `ThrottleConfiguration`/`ThrottleManagerImpl` pattern from the `web3` module — add a `FilterRegistrationBean` with a Bucket4j token-bucket rate limiter scoped to `/api/*`, enforcing per-IP or global request-per-second limits.
4. **Set a JVM heap limit and configure OOM protection**: Ensure the container/JVM has a hard heap ceiling and that a `RejectedExecutionHandler` or circuit breaker (already partially configured in the Helm chart's `circuitBreaker` middleware) is tuned to shed load before OOM.

### Proof of Concept

```bash
# Prerequisites: rest-java service accessible at TARGET; wrk installed
TARGET="http://<host>/api/v1/network/nodes?limit=25"

# Step 1: Confirm ETag buffering is active (observe ETag header in response)
curl -v "$TARGET" 2>&1 | grep -i etag

# Step 2: Flood with concurrent requests to force heap exhaustion
wrk -t 16 -c 500 -d 60s "$TARGET"

# Step 3: Observe degradation of transaction-related endpoints during the flood
# In a second terminal, measure latency on a transaction endpoint:
while true; do
  curl -o /dev/null -s -w "%{time_total}\n" \
    "http://<host>/api/v1/network/fees"
  sleep 0.5
done

# Expected result: latency on /network/fees climbs from <100ms to seconds or
# connection timeouts as JVM GC pressure mounts; JVM logs show repeated
# full GC events or OutOfMemoryError.
``` [1](#0-0)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```
