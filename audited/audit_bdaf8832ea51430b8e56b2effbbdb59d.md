### Title
Unauthenticated Health Endpoint Exposes Cluster State for Time-Series Profiling

### Summary
The `SubscriberHealthIndicator.health()` method feeds the `/actuator/health/cluster` endpoint, which is publicly exposed via an ingress with no authentication and TLS disabled by default. An unprivileged external attacker can continuously poll this endpoint to build a time-series record of UP/DOWN/UNKNOWN transitions, reliably inferring deployment events, pod restarts, and maintenance windows without any credentials.

### Finding Description
**Code location:** `monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java`, `health()` method, lines 59–63; ingress configuration at `charts/hedera-mirror-monitor/values.yaml`, lines 91–99.

The `health()` method aggregates three internal health signals — REST network stake reachability (`restNetworkStakeHealth()`), publish transaction rate (`publishing()`), and subscription rate (`subscribing()`) — and returns a `Health` object with `Status.UP`, `Status.DOWN`, or `Status.UNKNOWN`. [1](#0-0) 

The Helm chart's ingress is **enabled by default** and routes `/actuator/health/cluster` to the public internet with no authentication annotations and TLS explicitly disabled: [2](#0-1) 

There is no Spring Security configuration anywhere in the monitor module (no `SecurityConfig.java`, no `management.endpoints` restriction in `application.yml` — the only file in `monitor/src/main/resources/` is `banner.txt`). No rate limiting, no IP allowlist, and no authentication middleware is applied to this path.

The `restNetworkStakeHealth()` method also embeds error details (HTTP status codes, exception messages) into the `Health` object: [3](#0-2) 

### Impact Explanation
An attacker polling `/actuator/health/cluster` at regular intervals (e.g., every 5–10 seconds) obtains a timestamped stream of UP/DOWN/UNKNOWN transitions. These transitions directly correlate with:
- **Deployments**: UP → DOWN → UP pattern during rolling updates.
- **Pod restarts**: Brief DOWN spikes.
- **Maintenance windows**: Sustained DOWN or UNKNOWN periods.
- **REST API outages**: UNKNOWN/DOWN caused by `restNetworkStakeHealth()` failures, which include the upstream HTTP status code in the response detail.

This constitutes operational intelligence disclosure about the Hedera mirror node infrastructure, enabling an adversary to time attacks during known degraded states or to map the deployment cadence of the network.

### Likelihood Explanation
Preconditions are minimal: the attacker needs only network access to the ingress IP/hostname, which is publicly routable by default (`ingress.enabled: true`, `host: ""`). No credentials, tokens, or special tooling are required — a simple `curl` loop suffices. The endpoint is stateless and idempotent, making automated polling trivially repeatable and undetectable without access logging and anomaly detection.

### Recommendation
1. Add authentication to the actuator health endpoint. Either configure Spring Security to require credentials for `/actuator/**` beyond liveness/readiness probes, or add ingress-level authentication annotations (e.g., `nginx.ingress.kubernetes.io/auth-type: basic`).
2. Restrict the ingress to only expose liveness/readiness paths needed by external load balancers; move `/actuator/health/cluster` behind an authenticated path or remove it from the ingress entirely.
3. Enable TLS on the ingress (`tls.enabled: true`) to prevent passive traffic interception.
4. Set `management.endpoint.health.show-details=never` (or `when-authorized`) explicitly in application configuration to suppress detail leakage even if the endpoint remains accessible.
5. Implement rate limiting at the ingress layer.

### Proof of Concept
```bash
# Poll the unauthenticated health endpoint every 5 seconds and timestamp each response
while true; do
  echo -n "$(date -u +%Y-%m-%dT%H:%M:%SZ) "
  curl -s http://<monitor-ingress-host>/actuator/health/cluster | jq -r '.status'
  sleep 5
done
```
Output example during a rolling deployment:
```
2024-01-15T10:00:00Z UP
2024-01-15T10:00:05Z UP
2024-01-15T10:00:10Z DOWN       # <-- deployment started
2024-01-15T10:00:15Z DOWN
2024-01-15T10:00:20Z UP         # <-- new pod healthy
```
The attacker records this stream indefinitely, building a complete operational timeline of the cluster with zero privileges.

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L59-63)
```java
    public Mono<Health> health() {
        return restNetworkStakeHealth()
                .flatMap(health ->
                        health.getStatus() == Status.UP ? publishing().switchIfEmpty(subscribing()) : Mono.just(health))
                .doOnNext(this::recordHealthMetric);
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L93-121)
```java
    private Mono<Health> restNetworkStakeHealth() {
        return restApiClient
                .getNetworkStakeStatusCode()
                .flatMap(statusCode -> {
                    if (statusCode.is2xxSuccessful()) {
                        return UP;
                    }

                    var status = statusCode.is5xxServerError() ? Status.DOWN : Status.UNKNOWN;
                    var statusMessage =
                            String.format("Network stake status is %s with status code %s", status, statusCode.value());
                    log.error(statusMessage);
                    return health(status, statusMessage);
                })
                .timeout(Duration.ofSeconds(5))
                .onErrorResume(e -> {
                    var status = Status.UNKNOWN;
                    // Connection issue can be caused by database being down, since the rest API service will become
                    // unavailable eventually
                    var rootCause = ExceptionUtils.getRootCause(e);
                    if (rootCause instanceof ConnectException || rootCause instanceof TimeoutException) {
                        status = Status.DOWN;
                    }

                    var statusMessage =
                            String.format("Network stake status is %s with error: %s", status, e.getMessage());
                    log.error(statusMessage);
                    return health(status, statusMessage);
                });
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
