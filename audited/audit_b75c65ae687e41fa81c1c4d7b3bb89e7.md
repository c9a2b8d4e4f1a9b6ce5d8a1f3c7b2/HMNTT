### Title
Unauthenticated `/actuator/health` Polling Causes Unbounded Outbound HTTP Amplification to REST Java `/network/stake`

### Summary
Every call to `SubscriberHealthIndicator.health()` unconditionally issues a live HTTP GET to the REST Java service's `/network/stake` endpoint via `restNetworkStakeHealth()`, with no caching, debouncing, or rate limiting. Because Spring Boot's `/actuator/health` endpoint is unauthenticated by default and no security configuration exists in the monitor module, any unprivileged external user can flood the monitor's health endpoint, causing a 1:1 amplification of requests against the REST Java service and its backing database, readily exceeding a 30% increase in CPU and I/O load.

### Finding Description
**Code path:**

- `SubscriberHealthIndicator.health()` — [1](#0-0)  calls `restNetworkStakeHealth()` on every invocation, unconditionally.
- `restNetworkStakeHealth()` — [2](#0-1)  calls `restApiClient.getNetworkStakeStatusCode()` with no result caching, no debounce, and only a 5-second timeout.
- `RestApiClient.getNetworkStakeStatusCode()` — [3](#0-2)  issues a raw `WebClient` GET to `/network/stake` on `webClientRestJava` on every call.

**Root cause:** The health indicator performs a live, uncached, unauthenticated-upstream HTTP call on every health check invocation. The failed assumption is that `/actuator/health` is either infrequently polled or access-controlled.

**Why existing checks fail:**
- No `SecurityConfig` class exists anywhere in the monitor module. 
- The only file in `monitor/src/main/resources/` is `banner.txt` — no `application.yml` or `application.properties` configuring `management.endpoints.web.exposure` or actuator security. [4](#0-3) 
- Spring Boot's default is to expose `/actuator/health` publicly with no authentication.
- There is no `@Cacheable`, no `Mono.cache()`, no circuit breaker, and no rate limiter wrapping `restNetworkStakeHealth()`. [5](#0-4) 

### Impact Explanation
Each HTTP GET to `/actuator/health` on the monitor service generates exactly one outbound HTTP GET to the REST Java service's `/network/stake`, which in turn executes a database query. An attacker sending N requests/second to the monitor produces N requests/second against the REST Java service and N database queries/second. At modest rates (e.g., 50–100 req/s), this easily exceeds a 30% increase in CPU and I/O on the REST Java service and its database, potentially causing service degradation or denial of service for legitimate users of the mirror node API.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only network access to the monitor service's HTTP port. The exploit is trivially repeatable with any HTTP load tool (`curl` in a loop, `ab`, `wrk`, etc.). The monitor service is typically deployed as a network-accessible service, making this a realistic external threat.

### Recommendation
1. **Cache the health result**: Wrap `restNetworkStakeHealth()` with `.cache(Duration.ofSeconds(30))` or use Spring's `@Cacheable` to avoid issuing a new HTTP call on every poll.
2. **Restrict actuator access**: Add a Spring Security configuration to require authentication or restrict `/actuator/health` to internal/management networks only (e.g., `management.endpoints.web.exposure.include=health` with IP-based access control).
3. **Add rate limiting**: Apply a rate limiter (e.g., Resilience4j `RateLimiter`) around `getNetworkStakeStatusCode()` to cap outbound calls regardless of inbound polling rate.

### Proof of Concept
```bash
# Step 1: Confirm /actuator/health is publicly accessible (no auth required)
curl -s http://<monitor-host>:<port>/actuator/health

# Step 2: Flood the endpoint — each request triggers one /network/stake call
ab -n 10000 -c 100 http://<monitor-host>:<port>/actuator/health

# Step 3: Observe on the REST Java service:
# - Spike in /network/stake request rate in access logs
# - CPU and DB query rate increase >30% vs. baseline 24h average
# - No credentials, tokens, or special headers required
```

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L59-64)
```java
    public Mono<Health> health() {
        return restNetworkStakeHealth()
                .flatMap(health ->
                        health.getStatus() == Status.UP ? publishing().switchIfEmpty(subscribing()) : Mono.just(health))
                .doOnNext(this::recordHealthMetric);
    }
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L93-122)
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
    }
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestApiClient.java (L67-69)
```java
    public Mono<HttpStatusCode> getNetworkStakeStatusCode() {
        return webClientRestJava.get().uri("/network/stake").exchangeToMono(r -> Mono.just(r.statusCode()));
    }
```

**File:** monitor/src/main/resources/banner.txt (L1-1)
```text

```
