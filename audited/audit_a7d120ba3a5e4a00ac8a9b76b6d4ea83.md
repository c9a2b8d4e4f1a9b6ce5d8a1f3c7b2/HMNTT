### Title
Unauthenticated Health Endpoint Flooding Causes Fail-Open Prometheus Query Exhaustion, Permanently Masking Importer Lag

### Summary
`ImporterLagHealthIndicator.health()` issues a live Prometheus PromQL query on every invocation with no rate limiting, no circuit breaker, and no result caching. The ingress exposes `/actuator/health/cluster` publicly with zero authentication or rate-limit annotations. Any exception from the Prometheus client — including connection timeouts caused by query-rate exhaustion — is silently swallowed and the method unconditionally returns `Health.up()`, permanently hiding any real importer lag condition from operators.

### Finding Description

**Code path:**

`monitor/src/main/java/org/hiero/mirror/monitor/health/ImporterLagHealthIndicator.java`, lines 47–62:

```java
@Override
public Health health() {
    if (!properties.isEnabled()) {
        return up();
    }
    final var query = buildLagQuery();
    try {
        final var resp = prometheusClient.query(query);   // live HTTP call every invocation
        return evaluate(resp);
    } catch (final Exception e) {                         // catches ALL exceptions
        log.warn("Importer lag health check failed; returning UP: {}", e.getMessage());
        return up();                                      // fail-open: always UP on any error
    }
}
```

Every call to the Spring Boot actuator health endpoint triggers `health()`, which in turn issues the complex PromQL query defined in `PROMETHEUS_LAG_QUERY` (lines 24–42) via `PrometheusApiClient.query()` (a synchronous blocking HTTP call with a configurable timeout, default 5 s per `ImporterLagHealthProperties` line 64).

**Root cause — two compounding flaws:**

1. **No invocation guard**: There is no rate limiter, circuit breaker, or cached result. Every HTTP GET to `/actuator/health/cluster` fires a fresh Prometheus query.
2. **Unconditional fail-open**: The `catch (final Exception e)` block on line 58 traps every possible failure — network timeout, connection refused, HTTP 5xx from Prometheus, `RestClientException` — and returns `Health.up()` in all cases.

**Exposure surface:**

`charts/hedera-mirror-monitor/values.yaml` lines 91–99 show the ingress is enabled by default, routes `/actuator/health/cluster` to the pod, carries **empty annotations** (`annotations: {}`), and has TLS disabled. There is no nginx rate-limit annotation, no IP allowlist, and no authentication requirement.

```yaml
ingress:
  annotations: {}          # no rate-limit, no auth
  enabled: true
  hosts:
    - host: ""
      paths: ["/actuator/health/cluster"]
```

A grep across the entire `monitor/` tree finds zero uses of `RateLimiter`, `CircuitBreaker`, `Resilience4j`, or `management.endpoint.health.cache`, confirming no mitigations exist.

**Exploit flow:**

1. Attacker sends a sustained flood of `GET /actuator/health/cluster` requests to the public ingress IP.
2. Each request causes Spring Boot to invoke `ImporterLagHealthIndicator.health()`, which calls `PrometheusApiClient.query()`.
3. Prometheus receives far more concurrent PromQL evaluations than it can serve; queries queue, then time out after 5 s.
4. `RestClientException` (or `ResourceAccessException`) propagates up to the `catch (Exception e)` block.
5. `health()` logs a warning and returns `Health.up()`.
6. The composite `/actuator/health/cluster` endpoint reports UP to every caller — including the operator dashboard and any automated alerting that polls this endpoint.
7. A genuine importer lag (e.g., stream processing falling hundreds of seconds behind) goes undetected for the entire duration of the flood.

### Impact Explanation

The `ImporterLagHealthIndicator` is the sole automated signal that the mirror-node importer has fallen critically behind in processing Hedera record-stream files. When it is forced to return UP by this attack, operators lose visibility into a real lag event. Downstream consumers of the mirror node (exchanges, wallets, dApps) continue to receive stale data without any alert being raised. The attacker can sustain this blind spot indefinitely with a modest, unauthenticated HTTP flood, effectively suppressing the monitoring layer while a separate degradation or attack on the importer proceeds undetected.

### Likelihood Explanation

The attack requires no credentials, no special network position, and no knowledge beyond the public ingress hostname. The only tool needed is a standard HTTP load generator (e.g., `wrk`, `ab`, `hey`). The PromQL query is moderately expensive (multi-series rate + join), so Prometheus saturation is achievable at relatively low request rates. The attack is fully repeatable and can be automated. The default 5-second Prometheus timeout means each attacker request holds a Prometheus worker for up to 5 seconds, amplifying the load significantly.

### Recommendation

1. **Enable Spring Boot health caching**: Set `management.endpoint.health.cache.time-to-live=30s` (or similar) so repeated calls within the window reuse the last computed result without re-querying Prometheus.
2. **Add a circuit breaker**: Wrap `prometheusClient.query()` with Resilience4j `@CircuitBreaker`; after N consecutive failures, open the circuit and return a configurable fallback status (e.g., `UNKNOWN`) rather than `UP`.
3. **Change the fail-open default**: On Prometheus query failure, return `Health.unknown()` instead of `Health.up()` so operators are alerted to the monitoring gap rather than receiving a false positive.
4. **Rate-limit the ingress**: Add nginx rate-limit annotations (e.g., `nginx.ingress.kubernetes.io/limit-rps`) to the monitor ingress, or restrict `/actuator/health/cluster` to internal cluster traffic only.
5. **Separate the lag check from the on-demand health path**: Run the Prometheus query on a fixed schedule (e.g., `@Scheduled`) and cache the result; `health()` simply reads the cached value.

### Proof of Concept

```bash
# 1. Identify the public ingress address of the monitor service
MONITOR_HOST="<monitor-ingress-host>"

# 2. Flood the health endpoint (200 concurrent connections, sustained)
wrk -t8 -c200 -d120s "http://${MONITOR_HOST}/actuator/health/cluster"

# 3. While the flood runs, verify the endpoint always returns UP
#    even when the importer is genuinely lagging:
watch -n1 'curl -s http://${MONITOR_HOST}/actuator/health/cluster'
# Expected (incorrect) output: {"status":"UP"}

# 4. Simultaneously confirm Prometheus is saturated:
#    Query Prometheus directly for the same metric — it will time out or return errors.
curl "http://<prometheus-host>/api/v1/query?query=hiero_mirror_importer_stream_latency_seconds_sum"
# Expected: timeout or HTTP 503

# 5. Stop the flood; health() resumes returning the real status.
#    The lag event during the flood window was never surfaced.
```

The root cause lines are: [1](#0-0) [2](#0-1)

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/ImporterLagHealthIndicator.java (L55-61)
```java
        try {
            final var resp = prometheusClient.query(query);
            return evaluate(resp);
        } catch (final Exception e) {
            log.warn("Importer lag health check failed; returning UP: {}", e.getMessage());
            return up();
        }
```

**File:** charts/hedera-mirror-monitor/values.yaml (L91-99)
```yaml
ingress:
  annotations: {}
  enabled: true
  hosts:
    - host: ""
      paths: ["/actuator/health/cluster"]
  tls:
    enabled: false
    secretName: ""
```
