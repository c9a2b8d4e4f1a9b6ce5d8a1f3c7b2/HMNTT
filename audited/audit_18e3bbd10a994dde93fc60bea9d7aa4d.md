### Title
Unauthenticated Content-Length Header Spoofing Pollutes `hiero.mirror.restjava.request.bytes` Metric

### Summary
`MetricsFilter.recordMetrics()` reads the `Content-Length` request header directly and records it as the request byte count without validating it against the actual bytes received. Any unauthenticated external user can send a request to any valid API endpoint with an arbitrarily large `Content-Length` value, causing the `hiero.mirror.restjava.request.bytes` DistributionSummary to record inflated counts and permanently skewing capacity planning metrics.

### Finding Description
In `rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java`, the `recordMetrics()` method at lines 64–67:

```java
var contentLengthHeader = request.getHeader(CONTENT_LENGTH);
if (contentLengthHeader != null) {
    long contentLength = Math.max(0L, NumberUtils.toLong(contentLengthHeader));
    requestBytesProvider.withTags(tags).record(contentLength);
}
```

The code calls `request.getHeader(CONTENT_LENGTH)` — a value fully controlled by the client — and records it verbatim (after a floor of 0) into the Micrometer `DistributionSummary`. There is no cross-check against `request.getContentLength()` (which Tomcat derives from the actual stream) or any upper-bound cap. The only guard is `Math.max(0L, ...)`, which prevents negative values but does nothing to limit the maximum.

The recording only happens when `BEST_MATCHING_PATTERN_ATTRIBUTE` is set (line 61), meaning the request must match a known route. However, the REST Java API is a public read API with no authentication requirement, so any valid endpoint (e.g., `GET /api/v1/accounts`) satisfies this condition.

**Exploit flow:**
1. Attacker sends `GET /api/v1/accounts HTTP/1.1` with header `Content-Length: 9223372036854775807` (Long.MAX_VALUE).
2. Tomcat processes the GET request normally (no body expected, header is passed through).
3. Spring MVC matches the route and sets `BEST_MATCHING_PATTERN_ATTRIBUTE`.
4. `MetricsFilter.recordMetrics()` reads the header, computes `Math.max(0L, 9223372036854775807L)` = `9223372036854775807`, and calls `requestBytesProvider.withTags(tags).record(9223372036854775807L)`.
5. The `hiero.mirror.restjava.request.bytes` metric now contains a massively inflated total/mean. [1](#0-0) 

### Impact Explanation
The `hiero.mirror.restjava.request.bytes` DistributionSummary is permanently corrupted for the lifetime of the process (Micrometer cumulative counters are not reset). Operators relying on this metric for capacity planning, alerting, or billing estimation will receive misleading data. A single request with `Content-Length: 9223372036854775807` overflows the total-amount accumulator, making the mean and sum meaningless. Repeated attacks across different `(method, uri)` tag combinations can corrupt every metric series.

### Likelihood Explanation
No authentication, no rate limiting specific to this filter, and no special tooling is required. Any HTTP client (curl, Python requests) can craft the header in one line. The endpoint is publicly reachable. The attack is trivially repeatable and scriptable.

### Recommendation
Replace the blind header read with the actual bytes consumed by the server. Use `request.getContentLengthLong()` only as a fallback and cap it against a reasonable maximum, or — better — measure actual bytes read via a wrapping `HttpServletRequestWrapper` that counts stream bytes. At minimum, add an upper-bound sanity check:

```java
long contentLength = Math.min(
    Math.max(0L, NumberUtils.toLong(contentLengthHeader)),
    MAX_EXPECTED_REQUEST_BYTES   // e.g., configured max body size
);
```

### Proof of Concept
```bash
# Single request that corrupts the metric permanently
curl -s -o /dev/null \
  -H "Content-Length: 9223372036854775807" \
  "http://<mirror-node-host>/api/v1/accounts"

# Verify metric is corrupted
curl -s "http://<mirror-node-host>/actuator/prometheus" \
  | grep hiero_mirror_restjava_request_bytes
# Expected: sum will show an astronomically large value
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L64-67)
```java
            var contentLengthHeader = request.getHeader(CONTENT_LENGTH);
            if (contentLengthHeader != null) {
                long contentLength = Math.max(0L, NumberUtils.toLong(contentLengthHeader));
                requestBytesProvider.withTags(tags).record(contentLength);
```
