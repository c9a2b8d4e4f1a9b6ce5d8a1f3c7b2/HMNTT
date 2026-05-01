### Title
Unauthenticated HEAD Request Memory Amplification via ShallowEtagHeaderFilter on /api/* Endpoints

### Summary
The `etagFilter()` bean in `RestJavaConfiguration.java` registers a `ShallowEtagHeaderFilter` over all `/api/*` URL patterns with no authentication and no rate limiting in the `rest-java` module. Spring's `ShallowEtagHeaderFilter` always buffers the complete response body in memory to compute an MD5-based ETag — including for HTTP HEAD requests — but never transmits that body to the client. An unauthenticated attacker can flood the server with HEAD requests, causing repeated full database queries and full response-body allocations in heap memory while consuming zero outbound bandwidth, enabling a memory-based DoS with a higher sustainable request rate than an equivalent GET flood.

### Finding Description
**Exact code location:**
`rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java`, lines 42–46:

```java
@Bean
FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
    final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
    filterRegistrationBean.addUrlPatterns("/api/*");
    return filterRegistrationBean;
}
```

**Root cause:**
Spring's `ShallowEtagHeaderFilter` wraps the servlet response in a `ContentCachingResponseWrapper`. When the filter chain executes, the full response body is written into an in-memory byte array buffer. After the chain completes, the filter computes an MD5 hash of that buffer to produce the ETag value. For HEAD requests, Spring's `DispatcherServlet` internally promotes the request to GET to invoke the handler (so the full DB query and serialization run), the body is buffered by the filter, the ETag is computed, and then the body is discarded — it is never written to the wire. The buffer is held in heap memory for the duration of the request.

**Failed assumption:**
The configuration assumes that HEAD requests are cheap because no body is transmitted. In reality, the server performs the same work as a GET (full DB query + full response serialization + full in-memory buffering) with the only difference being that the body is not sent. This removes the attacker's bandwidth constraint entirely.

**Exploit flow:**
1. Attacker identifies a high-cardinality `/api/*` endpoint (e.g., a list endpoint returning many records).
2. Attacker sends a high volume of concurrent `HEAD /api/v1/<large-list-endpoint>` requests.
3. For each request: the full DB query executes, the full JSON response is serialized and buffered in a `ContentCachingResponseWrapper` byte array, the MD5 is computed, and the buffer is released.
4. With many concurrent requests, multiple large buffers coexist in heap simultaneously.
5. No rate limiting exists in the `rest-java` module (the `ThrottleConfiguration`/`ThrottleManagerImpl` classes are exclusively in the `web3` module and are not applied here).
6. No authentication is required to reach `/api/*` endpoints.

**Why existing checks are insufficient:**
- The `rest-java` config directory contains only `LoggingFilter`, `MetricsFilter`, `WebMvcConfiguration`, and `RestJavaConfiguration` — none implement rate limiting or request throttling.
- The `ThrottleConfiguration` bean (bucket4j-based) lives in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java` and is not present in the `rest-java` application context.
- No Spring Security configuration was found for `rest-java`, so no authentication gate exists before the filter executes.

### Impact Explanation
An attacker with no credentials can cause sustained heap pressure on the `rest-java` JVM. Each concurrent HEAD request holds a full response body buffer in memory (potentially hundreds of KB to several MB for list endpoints). With enough concurrent connections, this exhausts the JVM heap, triggering GC thrashing or `OutOfMemoryError`, making the API unavailable to all legitimate users. Because HEAD responses carry no body, the attacker's outbound bandwidth is not a limiting factor, allowing a higher sustainable request rate than a GET flood from the same connection.

### Likelihood Explanation
The attack requires no credentials, no special knowledge beyond the public API URL structure, and no sophisticated tooling — a simple `ab`, `wrk`, or `curl` loop suffices. The endpoint pattern `/api/*` is publicly documented. The absence of any rate limiting in the `rest-java` module means there is no server-side throttle to overcome. This is repeatable and automatable from a single host or botnet.

### Recommendation
1. **Disable ETag computation for HEAD requests** by subclassing `ShallowEtagHeaderFilter` and overriding `isEligibleForEtag()` to return `false` when `request.getMethod().equals("HEAD")`, or override `doFilterInternal` to skip body buffering for HEAD.
2. **Add rate limiting to rest-java**: introduce a bucket4j or Resilience4j rate-limiting filter in `RestJavaConfiguration` analogous to the `ThrottleConfiguration` in the `web3` module, applied before the ETag filter in the filter chain.
3. **Consider replacing `ShallowEtagHeaderFilter` with a `DeepContentCachingFilter` or a response-cache approach** (as used in the Node.js `rest` module) that stores pre-computed ETags so HEAD requests do not require re-executing the full handler.
4. **Set a maximum response size threshold** in the ETag filter so that responses above a configurable byte limit skip ETag computation entirely.

### Proof of Concept
```bash
# Flood the server with concurrent HEAD requests to a large-list endpoint
# No credentials required; adjust HOST and ENDPOINT as appropriate

wrk -t 10 -c 200 -d 60s \
    -s <(echo 'wrk.method = "HEAD"') \
    http://<HOST>/api/v1/transactions?limit=100

# Alternatively with Apache Bench:
ab -n 100000 -c 200 -m HEAD \
    http://<HOST>/api/v1/transactions?limit=100

# Monitor JVM heap on the server:
# jstat -gcutil <PID> 1000
# Expected: heap usage climbs steadily; GC overhead increases;
# eventually OOM or severe latency degradation for all /api/* clients.
```