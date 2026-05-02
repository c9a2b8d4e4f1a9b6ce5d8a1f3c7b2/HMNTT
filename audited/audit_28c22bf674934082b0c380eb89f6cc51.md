### Title
Unbounded Response Buffering via `ShallowEtagHeaderFilter` Enables Resource Exhaustion on `/api/*`

### Summary
The `etagFilter()` bean in `RestJavaConfiguration` registers Spring's `ShallowEtagHeaderFilter` across all `/api/*` endpoints with no accompanying rate limiting in the `rest-java` module. `ShallowEtagHeaderFilter` buffers the entire response body in memory and computes an MD5 hash on every request regardless of whether the client sends `If-None-Match`. An unprivileged attacker flooding these endpoints with high-volume requests forces repeated full DB execution, full in-memory response buffering, and MD5 computation per request, degrading service for legitimate users.

### Finding Description
**Code location:** `rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java`, `etagFilter()`, lines 42–46.

```java
@Bean
FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
    final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
    filterRegistrationBean.addUrlPatterns("/api/*");
    return filterRegistrationBean;
}
```

**Root cause:** `ShallowEtagHeaderFilter` wraps every response in a `ContentCachingResponseWrapper`, which accumulates the full response body in a byte array before flushing. It then computes an MD5 digest of that buffer to produce the ETag value. This happens unconditionally on every request — there is no server-side response cache. The filter only saves bandwidth (via HTTP 304) when the client cooperates by sending a matching `If-None-Match` header. An attacker simply omits that header (or varies it) and the server performs full work every time.

**No rate limiting in `rest-java`:** The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`, bucket4j) exists exclusively in the `web3` module for contract-call endpoints. The `rest-java` config directory contains only `LoggingFilter`, `MetricsFilter`, and `RestJavaConfiguration` — no request-rate limiter is registered for `/api/*`.

**Exploit flow:**
1. Attacker opens many concurrent connections (or uses a single high-throughput client) and sends GET requests to any `/api/*` endpoint (e.g., `/api/v1/transactions?timestamp=gt:<random_value>`).
2. Each request bypasses any ETag short-circuit because no `If-None-Match` is sent.
3. The server executes the full DB query, serializes the response, buffers it entirely in heap memory inside `ContentCachingResponseWrapper`, computes MD5, and writes the response.
4. Under sustained load, heap pressure grows proportionally to (concurrent requests × average response size), and CPU is consumed by repeated MD5 computation and DB I/O.

### Impact Explanation
Legitimate API consumers experience increased latency and eventual request failures (OOM errors, thread-pool exhaustion, GC pressure) as the attacker consumes server resources. The `ShallowEtagHeaderFilter` amplifies per-request memory cost compared to a streaming response: without it, the response would be written directly to the socket; with it, the full body is held in heap until the MD5 is computed. This is classified as griefing/DoS with no direct economic damage to network participants, matching the stated scope.

### Likelihood Explanation
No authentication or rate limiting is required. Any external client with network access to the REST Java service can execute this attack using standard HTTP tooling (`wrk`, `ab`, `curl` in a loop). The attack is trivially repeatable and requires no special knowledge beyond knowing the `/api/*` URL pattern, which is publicly documented.

### Recommendation
1. **Add rate limiting to `rest-java`:** Introduce a `FilterRegistrationBean` for a rate-limiting filter (e.g., bucket4j servlet filter or a custom `OncePerRequestFilter`) in `RestJavaConfiguration`, mirroring the pattern already used in the `web3` module's `ThrottleConfiguration`.
2. **Scope the ETag filter narrowly:** If ETags are only needed on specific, cacheable, low-cardinality endpoints, restrict `addUrlPatterns` to those paths rather than the entire `/api/*` wildcard.
3. **Consider response size limits:** Enforce maximum response sizes before buffering to bound per-request heap usage.
4. **Deploy an upstream rate limiter:** Place an API gateway or reverse proxy (e.g., nginx `limit_req`, Envoy, or a cloud WAF) in front of the service as a defense-in-depth measure.

### Proof of Concept
```bash
# Flood /api/v1/transactions with unique timestamps to ensure distinct responses and no ETag reuse
for i in $(seq 1 10000); do
  curl -s "http://<host>/api/v1/transactions?timestamp=gt:${i}000000000" \
       -H "Accept: application/json" \
       -o /dev/null &
done
wait
```
Each iteration triggers a full DB query, full response buffering in `ContentCachingResponseWrapper`, and MD5 computation. Running this at scale (e.g., with `wrk -t 16 -c 200 -d 60s`) will produce measurable heap growth and CPU saturation on the `rest-java` service with no rate-limit rejection, while legitimate requests experience degraded response times or timeouts.