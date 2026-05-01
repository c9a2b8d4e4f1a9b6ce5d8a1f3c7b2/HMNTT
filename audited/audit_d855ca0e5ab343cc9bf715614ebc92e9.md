### Title
Unauthenticated `/actuator/health` Polling Triggers Unbounded Outbound HTTP Calls, Exhausting WebClient Connection Pool

### Summary
Every call to `SubscriberHealthIndicator.health()` unconditionally issues a live outbound HTTP request to the mirror node REST API (`/network/stake`) with no result caching, no rate limiting, and no authentication on the actuator endpoint. An unprivileged attacker who can reach the monitor's port can flood the health endpoint, exhausting Reactor Netty's connection pool and causing legitimate Kubernetes liveness/readiness probes to fail, which restarts the monitor pod and blinds it to a real network shutdown.

### Finding Description
**Exact code path:**

`SubscriberHealthIndicator.health()` (line 59–64) always calls `restNetworkStakeHealth()` first:

```java
// SubscriberHealthIndicator.java lines 59-64
public Mono<Health> health() {
    return restNetworkStakeHealth()
            .flatMap(health ->
                    health.getStatus() == Status.UP ? publishing().switchIfEmpty(subscribing()) : Mono.just(health))
            .doOnNext(this::recordHealthMetric);
}
```

`restNetworkStakeHealth()` (lines 93–121) issues a real outbound HTTP GET to `/network/stake` on every invocation:

```java
// RestApiClient.java line 68
return webClientRestJava.get().uri("/network/stake").exchangeToMono(r -> Mono.just(r.statusCode()));
```

with a 5-second timeout (line 107) but **no caching, no deduplication, and no back-pressure limit**.

**Root cause / failed assumption:** Spring Boot does not cache `ReactiveHealthIndicator` results unless `management.endpoint.health.cache.time-to-live` is explicitly configured. No such configuration exists in the codebase (no `application.yml`/`.properties` found under `monitor/src/main/resources/`). No `SecurityConfig` class exists in the monitor module, so the actuator health endpoint is publicly accessible by Spring Boot's default.

**Why existing checks are insufficient:**
- The 5-second `timeout()` (line 107) only bounds individual request duration; it does not limit concurrency.
- The `onErrorResume` (lines 108–121) gracefully handles errors but does not prevent new connections from being opened.
- Reactor Netty's default `ConnectionProvider` has a max-connections ceiling (typically 500). Each attacker request holds one connection for up to 5 seconds. At 100 req/s, the pool saturates in ~5 seconds.

### Impact Explanation
Once the Reactor Netty connection pool to the REST API is saturated, all subsequent `restNetworkStakeHealth()` calls queue indefinitely or time out. The Kubernetes liveness probe (`/health/liveness`, deployment.yaml line 35–39) and readiness probe (lines 44–48) both hit the same Spring Boot actuator stack. When those probes time out (`timeoutSeconds: 2`), Kubernetes marks the pod unhealthy and restarts it. During the restart window the monitor cannot evaluate `SubscriberHealthIndicator` at all, meaning a genuine total network shutdown (the critical scope) goes undetected. The `CLUSTER_UP` gauge (line 31, 45–47) also stops updating, silently staling Prometheus/Grafana alerting.

### Likelihood Explanation
The monitor's actuator port (3000, deployment.yaml line 41) is exposed on the pod. If a Kubernetes `Service` or `Ingress` exposes it (common for scraping Prometheus metrics or external health dashboards), any network-reachable client with no credentials can exploit this. The attack requires only an HTTP client capable of sending concurrent GET requests — no authentication, no tokens, no special protocol knowledge. It is trivially repeatable and automatable with tools like `ab`, `wrk`, or `curl` in a loop.

### Recommendation
1. **Cache health results**: Set `management.endpoint.health.cache.time-to-live=10s` (or similar) in `application.properties` so repeated polls reuse the last computed result instead of issuing new outbound HTTP calls.
2. **Restrict actuator access**: Add Spring Security to the monitor module and require authentication (or IP allowlist) for `/actuator/**` endpoints, or bind the management port to a separate internal-only port via `management.server.port` and block it at the network layer.
3. **Bound WebClient concurrency**: Configure a `ConnectionProvider` with `maxConnections` and `pendingAcquireTimeout` on `webClientRestJava` so that health-check-driven connections cannot monopolize the pool.
4. **Rate-limit at ingress**: Apply an ingress-level rate limit on the health endpoint path.

### Proof of Concept
```bash
# Precondition: monitor actuator port (3000) is reachable
# Step 1: saturate the connection pool with concurrent health polls
for i in $(seq 1 200); do
  curl -s http://<monitor-host>:3000/actuator/health &
done
wait

# Step 2: observe that legitimate Kubernetes probes now time out
# (check pod events: "Liveness probe failed: Get ... context deadline exceeded")
kubectl describe pod <monitor-pod> | grep -A5 "Liveness\|Readiness"

# Step 3: pod is restarted; during restart window, no health evaluation occurs
# A real network shutdown during this window produces no alert
```