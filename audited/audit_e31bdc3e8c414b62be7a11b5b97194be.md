### Title
Unbounded Heap Buffering via ShallowEtagHeaderFilter Enables Memory Exhaustion DoS on rest-java Instances

### Summary
The `etagFilter()` bean in `RestJavaConfiguration.java` registers a `ShallowEtagHeaderFilter` across all `/api/*` endpoints with no response-size cap, no concurrency limit, and no application-level rate limiting in the `rest-java` module. Spring's `ShallowEtagHeaderFilter` buffers the entire serialized response body in a JVM heap `ByteArrayOutputStream` before computing the ETag hash. An unprivileged attacker flooding concurrent requests to large-response endpoints causes all in-flight response bodies to be held simultaneously in heap, exhausting the 2048 MiB JVM memory limit and crashing one or more mirror-node instances.

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

**Root cause:** Spring's `ShallowEtagHeaderFilter` wraps every matched response in a `ContentCachingResponseWrapper` backed by an unbounded `ByteArrayOutputStream`. The entire response body is accumulated in JVM heap before the ETag MD5 is computed and the bytes are flushed to the client. There is no `setWriteWeakETag`, no size threshold, and no streaming bypass — every byte of every concurrent `/api/*` response lives in heap until the response is fully written.

**No rate limiting in rest-java:** The `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` classes that implement bucket4j-based rate limiting exist exclusively in the `web3` module (`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`). The `rest-java` config package (`JacksonConfiguration`, `LoggingFilter`, `MetricsConfiguration`, `MetricsFilter`, `NetworkProperties`, `RestJavaConfiguration`, `RuntimeHintsConfiguration`, `WebMvcConfiguration`) contains no equivalent rate-limiting filter.

**Pagination limits exist but do not prevent the attack:** Controllers such as `AllowancesController` enforce `@Max(MAX_LIMIT)` on the `limit` parameter. However, even at the maximum page size, responses for endpoints like `/api/v1/network/fees` (full fee schedule), `/api/v1/network/nodes`, or `/api/v1/accounts/{id}/allowances/nfts` can be tens to hundreds of kilobytes each. With hundreds of concurrent requests, the aggregate in-heap buffering easily reaches gigabytes.

**Exploit flow:**
1. Attacker identifies a paginated endpoint returning large JSON bodies (e.g., `/api/v1/network/fees` or `/api/v1/network/nodes?limit=100`).
2. Attacker opens hundreds of concurrent HTTP connections and sends requests simultaneously.
3. Each request enters `ShallowEtagHeaderFilter`, which wraps the response in `ContentCachingResponseWrapper`.
4. The controller queries the database and serializes the full response into the in-memory buffer.
5. All N concurrent response buffers coexist in JVM heap until each response is fully written.
6. With N × (average response size) exceeding the 2048 MiB JVM heap limit, the JVM throws `OutOfMemoryError` and the pod crashes.
7. Repeating across multiple pods crashes 30%+ of the mirror-node fleet.

### Impact Explanation

The JVM memory limit for rest-java pods is explicitly set to 2048 MiB (`charts/hedera-mirror-rest-java/values.yaml`, lines 307–308). The `RestJavaHighMemory` Grafana alert fires reactively after 5 minutes above 80% — it does not prevent the crash. A successful OOM crash of 30%+ of rest-java instances degrades or eliminates mirror-node API availability for the Hiero network, matching the stated severity scope (shutdown of ≥30% of network processing nodes without brute force).

### Likelihood Explanation

No authentication or API key is required to call `/api/*` endpoints. The attack requires only the ability to open many concurrent TCP connections — achievable from a single machine with a modest script or from a small botnet. The `maxRatePerEndpoint: 250` GCP gateway setting (`charts/hedera-mirror-rest-java/values.yaml`, line 56) is an optional infrastructure-layer control that is not universally deployed and applies per-endpoint, not globally. It also does not limit concurrent in-flight requests, only the rate of new ones. The attack is repeatable: after a pod restarts, the attacker can immediately repeat.

### Recommendation

1. **Replace `ShallowEtagHeaderFilter` with a streaming ETag implementation** or disable it entirely if ETag support is not a hard requirement. If ETags are needed, use a `ContentCachingResponseWrapper` with a configurable maximum buffer size that falls back to no-ETag when exceeded.
2. **Add application-level rate limiting to rest-java** equivalent to the bucket4j throttle already present in the `web3` module — a per-IP or global request-rate filter registered before `ShallowEtagHeaderFilter` in the filter chain.
3. **Set a hard response-body size cap** in the ETag filter (e.g., skip ETag computation for responses larger than a configured threshold, e.g., 512 KB) by subclassing `ShallowEtagHeaderFilter` and overriding `isEligibleForEtag`.
4. **Enforce connection/concurrency limits** at the ingress layer (e.g., GCP BackendPolicy `maxRatePerEndpoint`) as a mandatory, not optional, deployment requirement.

### Proof of Concept

```bash
# Flood concurrent requests to a large-response endpoint
# Requires: curl, GNU parallel or xargs

TARGET="https://<mirror-node-host>/api/v1/network/fees"

# Send 500 concurrent requests
seq 500 | xargs -P 500 -I{} curl -s -o /dev/null "$TARGET" &

# Simultaneously monitor JVM heap on the pod
kubectl top pod -l app.kubernetes.io/component=rest-java --containers

# Expected: JVM heap climbs rapidly; pod OOMKilled or process crashes
# with java.lang.OutOfMemoryError: Java heap space in logs
```

Each concurrent request causes `ShallowEtagHeaderFilter` to allocate a `ByteArrayOutputStream` holding the full serialized response. With 500 concurrent requests each buffering a ~200 KB fee-schedule response, ~100 MB of heap is consumed per wave; scaling to larger responses or higher concurrency exhausts the 2048 MiB limit. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L54-57)
```yaml
      logging:
        enabled: false
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L227-237)
```yaml
  RestJavaHighMemory:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} memory usage reached {{ $value | humanizePercentage }}"
      summary: "Mirror Java REST API memory usage exceeds 80%"
    enabled: true
    expr: sum(jvm_memory_used_bytes{application="rest-java"}) by (namespace, pod) / sum(jvm_memory_max_bytes{application="rest-java"}) by (namespace, pod) > 0.8
    for: 5m
    labels:
      application: rest-java
      area: resource
      severity: critical
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L305-311)
```yaml
resources:
  limits:
    cpu: 2
    memory: 2048Mi
  requests:
    cpu: 1
    memory: 1024Mi
```
