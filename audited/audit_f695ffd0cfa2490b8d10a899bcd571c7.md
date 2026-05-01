### Title
Fail-Open Health Indicator with No Rate Limiting Enables Lag-Masking via Prometheus Query Exhaustion

### Summary
`ImporterLagHealthIndicator.health()` makes a live, synchronous HTTP call to Prometheus on every invocation with no rate limiting, caching, or circuit breaker. Any exception — including a timeout caused by flooding — is silently swallowed and returns `UP`. Because `/actuator/health/cluster` is publicly exposed via ingress with no authentication, an unprivileged attacker can flood this endpoint, exhaust the monitor's outbound Prometheus connection capacity, and force the health check to permanently return `UP` even when importer stream latency is critically elevated.

### Finding Description

**Code path:**

`ImporterLagHealthIndicator.health()` — lines 47–62:
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
    } catch (final Exception e) {
        log.warn("Importer lag health check failed; returning UP: {}", e.getMessage());
        return up();   // ← fail-open: ANY exception → UP
    }
}
```

`PrometheusApiClient` uses `SimpleClientHttpRequestFactory` (lines 25–28), which creates a **new TCP connection per request** with no connection pooling. Under concurrent load this exhausts file descriptors or causes `ConnectException`/`SocketTimeoutException`, both of which are subclasses of `Exception` and are caught by the broad `catch` block above.

The default Prometheus query timeout is **5 seconds** (`ImporterLagHealthProperties` line 64). With no rate limiting, each concurrent health-check request holds a thread and an outbound socket for up to 5 seconds.

**Public exposure:**

`charts/hedera-mirror-monitor/values.yaml` line 96 exposes `/actuator/health/cluster` via ingress with no authentication and no middleware rate-limiting annotation. The only guard inside `health()` is `properties.isEnabled()` — a static config flag, not a security control.

**Why existing checks fail:**

- No Spring Boot health-endpoint cache TTL configured — every HTTP hit re-invokes `health()`.
- No `@RateLimiter`, `@CircuitBreaker`, or Resilience4j annotation on `health()`.
- `SimpleClientHttpRequestFactory` has no shared connection pool to bound concurrency.
- The `catch (Exception e)` block is intentionally broad and unconditionally returns `UP`.

### Impact Explanation

When the attacker sustains the flood, every Prometheus query either times out or fails with a connection error. The catch block returns `UP` for all of them. Operators and automated alerting systems observe a healthy cluster status while the actual importer stream latency (`hiero_mirror_importer_stream_latency_seconds`) may be far above the 20-second threshold. Transactions that depend on the importer being current (mirror node queries, downstream consumers) silently receive stale or missing data with no observable health signal. The monitor's own `hiero_mirror_monitor_health` gauge — which other clusters use to decide whether to route traffic — is also corrupted because `SubscriberHealthIndicator` reads cluster-up state that is influenced by the composite health result.

### Likelihood Explanation

The attack requires only unauthenticated HTTP GET requests to a publicly routable URL. No credentials, tokens, or special knowledge are needed. The attacker needs only enough concurrency to saturate the monitor pod's outbound socket budget (the pod is limited to 500m CPU / 768Mi memory per `values.yaml` lines 273–278), which is achievable from a single machine with a modest HTTP flood tool. The attack is repeatable and stateless — stopping and restarting it is trivial.

### Recommendation

1. **Add a result cache** — configure `management.endpoint.health.cache.time-to-live` (e.g., 10–15 s) so repeated calls within the window return the cached result without re-querying Prometheus.
2. **Add a circuit breaker** — wrap `prometheusClient.query(query)` with Resilience4j `@CircuitBreaker` so that after N consecutive failures the indicator opens the circuit and returns a configurable status (e.g., `UNKNOWN`) rather than `UP`.
3. **Replace `SimpleClientHttpRequestFactory`** with a pooled factory (e.g., `HttpComponentsClientHttpRequestFactory` backed by `PoolingHttpClientConnectionManager`) to bound the number of concurrent outbound connections.
4. **Restrict the health endpoint** — add an ingress rate-limit annotation (e.g., Traefik `rateLimit` middleware) on `/actuator/health/cluster`, or move it behind authentication.
5. **Change the fail-open default** — consider returning `UNKNOWN` instead of `UP` on Prometheus query failure, so the composite health status degrades visibly rather than masking the problem.

### Proof of Concept

```bash
# Precondition: /actuator/health/cluster is reachable at $MONITOR_HOST
# Step 1 – confirm normal behaviour (should return UP or DOWN based on real lag)
curl -s https://$MONITOR_HOST/actuator/health/cluster

# Step 2 – flood the endpoint with concurrent requests
# Each request causes a live Prometheus query (up to 5 s timeout)
seq 1 500 | xargs -P 200 -I{} \
  curl -s -o /dev/null https://$MONITOR_HOST/actuator/health/cluster &

# Step 3 – while flood is running, observe that all responses return {"status":"UP"}
# even if Prometheus is now timing out (verify via monitor logs:
#   "Importer lag health check failed; returning UP: ...")
watch -n1 'curl -s https://$MONITOR_HOST/actuator/health/cluster'

# Step 4 – confirm Prometheus queries are failing by tailing monitor pod logs
kubectl logs -f deploy/hedera-mirror-monitor | grep "lag health check failed"

# Expected result: sustained {"status":"UP"} responses with log lines confirming
# Prometheus query timeouts, while actual importer lag remains undetected.
```