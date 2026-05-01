### Title
WebClient Connection Leak via Unconsumed Response Body in `getNetworkStakeStatusCode()` Enables Connection Pool Exhaustion by Unauthenticated External Users

### Summary
`RestApiClient.getNetworkStakeStatusCode()` uses `exchangeToMono(r -> Mono.just(r.statusCode()))` which extracts the HTTP status code but never consumes or releases the response body. Per Spring WebClient's documented contract, this prevents the underlying TCP connection from being returned to Reactor Netty's connection pool, causing a connection leak on every invocation. Because the monitor's `/actuator/health/cluster` endpoint is publicly exposed via ingress with no rate limiting, an unauthenticated external attacker can flood it, exhaust the connection pool, and cause all subsequent health checks to time out and report `DOWN`.

### Finding Description

**Exact code location:**

`monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestApiClient.java`, line 68:
```java
public Mono<HttpStatusCode> getNetworkStakeStatusCode() {
    return webClientRestJava.get().uri("/network/stake").exchangeToMono(r -> Mono.just(r.statusCode()));
}
```

Called from `monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java`, lines 93–121 (`restNetworkStakeHealth()`), which is invoked on every call to `health()`.

**Root cause:**

Spring WebClient's `exchangeToMono` API transfers full responsibility for response body consumption to the caller. The Spring documentation explicitly states: *"Unlike retrieve(), when using exchange(), it is the responsibility of the application to consume any response content regardless of the scenario. Not doing so can cause a memory leak."* The lambda `r -> Mono.just(r.statusCode())` only reads the status code from the already-received response headers; the response body bytes remain buffered in Reactor Netty's pipeline. Because the body is never drained (no `r.releaseBody()`, no `r.bodyToMono(Void.class)`, no `r.toBodilessEntity()`), Reactor Netty cannot mark the connection as reusable and cannot return it to the pool. Each call permanently removes one connection from the pool until the server-side closes the TCP connection (which may take minutes depending on keep-alive settings).

**Exploit flow:**

1. The attacker identifies the publicly exposed health endpoint. `charts/hedera-mirror-monitor/values.yaml` configures the ingress with `paths: ["/actuator/health/cluster"]` and no `inFlightReq` or rate-limiting middleware (unlike other services in the chart suite).
2. The attacker sends a high volume of concurrent GET requests to `/actuator/health/cluster`.
3. Each request causes Spring Boot Actuator to invoke `SubscriberHealthIndicator.health()` → `restNetworkStakeHealth()` → `restApiClient.getNetworkStakeStatusCode()`.
4. Each invocation issues a real HTTP GET to the REST Java backend (`/network/stake`) via `webClientRestJava`, receives the response headers (status code), but never drains the body. The connection is leaked from Reactor Netty's pool.
5. Reactor Netty's default connection pool maximum (500 connections) is exhausted. New requests to `webClientRestJava` block waiting for a connection.
6. The 5-second `.timeout(Duration.ofSeconds(5))` at line 107 of `SubscriberHealthIndicator.java` fires for all pending health checks (they time out waiting for a pool slot, not for the network response).
7. `onErrorResume` at lines 108–121 catches the `TimeoutException`, sets `status = Status.DOWN`, and returns a DOWN health result.
8. The monitor cluster health reports DOWN continuously, triggering false network-shutdown alerts and potentially automated remediation actions.

**Why existing checks are insufficient:**

- **`.timeout(Duration.ofSeconds(5))`** (line 107): This timeout governs how long to wait for the `Mono<HttpStatusCode>` to emit a value. It does not release the already-leaked connection. Once the status code is emitted (fast, from response headers), the timeout has already been satisfied — but the connection is still held. Under pool exhaustion, the timeout fires because no connection is available to even start the request, not because the body was consumed.
- **`onErrorResume`** (lines 108–121): Error handling only; does not address the structural leak.
- **No `releaseBody()` call**: Nowhere in the call chain is `ClientResponse.releaseBody()` or any body-consuming method called.

### Impact Explanation

The monitor's health indicator is the authoritative signal for whether the Hiero network can confirm new transactions. A sustained false `DOWN` status from `SubscriberHealthIndicator` propagates to the cluster health endpoint, which is consumed by alerting systems and potentially by automated runbooks. Connection pool exhaustion in `webClientRestJava` also affects all other `RestApiClient` operations (e.g., `getNodes()`, `retrieve()`) that share the same `WebClient` instance when `restJava` is not separately configured, broadening the denial-of-service surface. The attack requires no authentication and no special network position.

### Likelihood Explanation

The attack requires only the ability to send HTTP GET requests to a publicly routable URL — no credentials, no tokens, no special protocol knowledge. The ingress path `/actuator/health/cluster` is enabled by default in the Helm chart with no rate limiting. A single attacker with a modest number of concurrent connections (a few hundred, well within reach of a single machine) can exhaust the default Reactor Netty pool. The attack is repeatable and self-sustaining: once the pool is exhausted, legitimate health checks also fail, keeping the pool drained.

### Recommendation

Replace `exchangeToMono(r -> Mono.just(r.statusCode()))` with a pattern that explicitly releases the response body before returning the status code:

```java
// Option 1: release body explicitly
public Mono<HttpStatusCode> getNetworkStakeStatusCode() {
    return webClientRestJava.get().uri("/network/stake")
        .exchangeToMono(r -> r.releaseBody().thenReturn(r.statusCode()));
}

// Option 2: use retrieve() with onStatus to capture non-2xx codes without throwing
public Mono<HttpStatusCode> getNetworkStakeStatusCode() {
    return webClientRestJava.get().uri("/network/stake")
        .exchangeToMono(r -> r.toBodilessEntity().map(e -> e.getStatusCode()));
}
```

Additionally, configure rate limiting on the `/actuator/health/cluster` ingress path (e.g., Traefik `inFlightReq` middleware, as used by other services in this chart suite) to limit the blast radius of any future similar issues.

### Proof of Concept

**Preconditions:** The monitor service is deployed with the default Helm chart; the ingress for `/actuator/health/cluster` is reachable from the attacker's machine.

**Steps:**

```bash
# 1. Confirm the endpoint is reachable and returns a valid health response
curl -s https://<monitor-host>/actuator/health/cluster

# 2. Flood the endpoint with concurrent requests to exhaust the connection pool
# Using Apache Bench: 10,000 requests, 200 concurrent
ab -n 10000 -c 200 https://<monitor-host>/actuator/health/cluster

# 3. While the flood is running, observe that new health check requests begin timing out
# and returning {"status":"DOWN"} with a reason containing "within 5000ms"
watch -n 1 'curl -s https://<monitor-host>/actuator/health/cluster'

# 4. Stop the flood; observe that the pool slowly recovers as the server closes
# idle TCP connections (may take 30–120 seconds depending on keep-alive settings)
```

**Expected result during attack:** All health check responses return `{"status":"DOWN","details":{"reason":"Network stake status is DOWN with error: ... did not complete within 5000ms"}}`, causing the monitor to signal a false total network shutdown.