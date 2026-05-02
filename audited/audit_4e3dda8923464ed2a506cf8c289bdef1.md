### Title
HTTP 429 Rate-Limit Response Causes Health Check to Emit `Status.UNKNOWN`, Short-Circuiting Partition Detection

### Summary
In `restNetworkStakeHealth()`, any 4xx HTTP response — including HTTP 429 (Too Many Requests) — is mapped to `Status.UNKNOWN`. Because the outer `health()` method only continues to the publishing/subscribing checks when the status is exactly `Status.UP`, a `Status.UNKNOWN` result causes an immediate short-circuit. An unprivileged external attacker who can flood the public `/network/stake` REST endpoint to trigger rate-limiting will cause the monitor to permanently report `UNKNOWN` instead of `DOWN`, masking a genuine cluster degradation.

### Finding Description

**Code path — `restNetworkStakeHealth()` (lines 93–122):**

```
statusCode.is2xxSuccessful() → false  (429 is 4xx)
statusCode.is5xxServerError() → false (429 is 4xx)
→ status = Status.UNKNOWN              (line 101)
→ returns health(UNKNOWN, …)
```

**Code path — `health()` (lines 59–63):**

```java
restNetworkStakeHealth()
  .flatMap(health ->
      health.getStatus() == Status.UP          // false for UNKNOWN
          ? publishing().switchIfEmpty(subscribing())
          : Mono.just(health))                 // short-circuits here
```

When `UNKNOWN` is returned, `publishing()` and `subscribing()` are **never evaluated**. If the cluster is genuinely degraded (publish/subscribe rates at zero, `failWhenInactive=true`), the correct result would be `Status.DOWN`. Instead the monitor emits `Status.UNKNOWN`.

`getNetworkStakeStatusCode()` (line 68 of `RestApiClient.java`) issues a plain unauthenticated GET to the public `/network/stake` endpoint and returns the raw HTTP status code with no retry or back-off logic. The `onErrorResume` handler (lines 108–121) only promotes `ConnectException` / `TimeoutException` to `DOWN`; a received 429 response is not an exception — it is a successfully received status code that falls through to the `UNKNOWN` branch.

The test suite at line 68 of `SubscriberHealthIndicatorTest.java` explicitly encodes this behaviour (`"1.0, 1.0, 400, UNKNOWN, false"`), confirming it is not a latent edge case but the designed (and therefore unguarded) path.

### Impact Explanation

When the cluster is genuinely down (publish/subscribe rates drop to zero and `failWhenInactive=true`), the correct health status is `DOWN`. An attacker who sustains a 429 condition on the REST API converts that `DOWN` into `UNKNOWN`. Alerting pipelines that treat `UNKNOWN` differently from `DOWN` (e.g., PagerDuty severity routing, Kubernetes liveness probes that only act on `DOWN`) will fail to fire, delaying or suppressing incident response during an actual outage. The `CLUSTER_UP` Prometheus gauge is set to `0` in both cases, but the health endpoint's JSON status field — consumed by orchestration and on-call tooling — differs.

### Likelihood Explanation

The Hiero mirror-node REST API is a public, unauthenticated HTTP service. No credentials, tokens, or network access beyond a standard internet connection are required. Sustaining enough request volume to keep a single endpoint rate-limited is well within the capability of a single commodity machine or a small botnet. The attack is repeatable and can be maintained indefinitely at low cost. Because the health check fires on every poll interval with no retry or jitter, a sustained 429 condition maps 1:1 to a sustained `UNKNOWN` health status.

### Recommendation

1. **Treat 429 as `DOWN`, not `UNKNOWN`.** Add an explicit branch before the generic 4xx fallthrough:
   ```java
   if (statusCode.value() == 429) {
       return health(Status.DOWN, "REST API rate-limited (429)");
   }
   ```
2. **Add retry with back-off inside `restNetworkStakeHealth()`** (e.g., `retryWhen(Retry.backoff(3, Duration.ofMillis(500)))`) so transient 429 responses do not immediately affect the health result.
3. **Do not short-circuit on `UNKNOWN`.** Consider evaluating publishing/subscribing checks regardless of the REST stake status, and composing the final status from all three signals.
4. **Add a test case for HTTP 429** that asserts `Status.DOWN` (or at minimum that publishing/subscribing checks are still evaluated).

### Proof of Concept

**Preconditions:**
- Mirror-node monitor is running and polling health.
- Cluster is degraded: publish/subscribe rates are 0, `failWhenInactive=true`.
- REST API is publicly reachable.

**Steps:**

1. Identify the REST API base URL from monitor configuration (e.g., `https://mainnet-public.mirrornode.hedera.com`).
2. Flood the `/api/v1/network/stake` endpoint from an unprivileged machine:
   ```bash
   while true; do
     curl -s -o /dev/null https://<REST_API>/api/v1/network/stake &
   done
   ```
3. Sustain until the REST API begins returning HTTP 429 to all clients (including the monitor process).
4. Poll the monitor's Spring Boot actuator health endpoint:
   ```bash
   curl http://<monitor-host>:8080/actuator/health
   ```
5. **Expected (correct) result:** `{"status":"DOWN"}` — cluster is degraded.
6. **Actual result:** `{"status":"UNKNOWN","details":{"reason":"Network stake status is UNKNOWN with status code 429"}}` — degradation is masked; publishing/subscribing checks are never reached.