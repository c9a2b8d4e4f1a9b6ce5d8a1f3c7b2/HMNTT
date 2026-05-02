### Title
Unauthenticated Request Flooding Enables Metric Manipulation via Unbounded `durationHistogram` Recording in `metricsMiddleware`

### Summary
The `metricsMiddleware` in `rest/middleware/metricsHandler.js` unconditionally records the wall-clock duration of every inbound request into `durationHistogram` with no application-level rate limiting. Because the `/api/v1/transactions` endpoint is publicly accessible without authentication, any unprivileged external user can flood it with requests, inflating the `api_request_duration_milliseconds` histogram's high percentile buckets. When Prometheus scrapes these samples, p99 latency alerting rules fire, potentially triggering operator intervention that alters how transaction history is served globally.

### Finding Description
**Code path:**
- `rest/middleware/metricsHandler.js`, `metricsMiddleware()`, lines 152–214
- `rest/server.js`, lines 88–92 (unconditional registration of the middleware for all routes)

**Root cause:**

At line 168, `startTime = Date.now()` is captured for every request that is not the metrics scrape path. At line 188, `duration = Date.now() - startTime` is computed on response finish. At line 208, `durationHistogram.record(duration, labels)` is called unconditionally with no guard, cap, or rate check:

```js
// lines 168, 188, 208
const startTime = Date.now();
...
const duration = Date.now() - startTime;
...
durationHistogram.record(duration, labels);
```

The labels include `path` (normalized to OpenAPI form, e.g. `/api/v1/transactions`) and `code`. Every request — regardless of source IP, frequency, or intent — contributes a sample.

**Why existing checks fail:**

- `authHandler.js` (lines 15–36): only sets a per-user response-size `limit` for authenticated users. It does not rate-limit request frequency and does not block unauthenticated users from reaching the route.
- No application-level rate-limiting middleware exists in `server.js` for the REST API. The middleware stack is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler → routes`.
- The Traefik `rateLimit` middleware in the Helm chart (`charts/hedera-mirror-rest/values.yaml`) is infrastructure-optional and not enforced at the application layer; it is absent by default in many deployment configurations and can be bypassed if the pod is accessed directly.
- The `web3` throttle (`ThrottleManagerImpl`) and Rosetta rate limiting are entirely separate services and do not apply here.

**Exploit flow:**

An attacker sends a sustained burst of HTTP GET requests to `/api/v1/transactions?account.id=0.0.1234`. Each request:
1. Passes through `metricsMiddleware` which captures `startTime`.
2. Hits the database (or times out), producing a real high-duration sample under load.
3. On `res.finish`, records that duration into `durationHistogram` with `path=/api/v1/transactions`.

Under sufficient load, the p99 bucket of `api_request_duration_milliseconds{path="/api/v1/transactions"}` spikes well above the configured `durationBuckets = [25, 100, 250, 500]` ms thresholds. Prometheus scrapes this and fires latency alerts. Operators, believing the transaction history endpoint is degraded, may apply mitigations (e.g., caching overrides, query restrictions, circuit-breaker changes) that affect all users.

### Impact Explanation
The attacker can reliably manipulate the `api_request_duration_milliseconds` histogram for any specific route without any credentials. This constitutes metric integrity compromise: the observability data no longer reflects genuine system health. Downstream consequences include false-positive alerting, operator fatigue, and — critically — operator-driven configuration changes to transaction history serving that affect all users globally. The impact is classified as availability/integrity of the monitoring plane with indirect effect on data-serving behavior.

### Likelihood Explanation
Preconditions are minimal: the REST API is a public-facing service by design, no authentication is required for `/api/v1/transactions`, and `metrics.enabled` defaults to `true`. The attack requires only an HTTP client capable of sending concurrent requests. It is repeatable, scriptable, and requires no special knowledge beyond the public API documentation. The absence of application-layer rate limiting makes sustained exploitation trivial.

### Recommendation
1. **Application-layer rate limiting**: Add a per-IP or global rate-limiting middleware (e.g., `express-rate-limit`) in `server.js` before `metricsHandler`, so that flood traffic is rejected before duration samples are recorded.
2. **Metric sampling guard**: In `metricsMiddleware`, consider skipping `durationHistogram.record()` for requests that were rate-limited or rejected at the ingress layer (e.g., check status code 429 before recording).
3. **Enforce infrastructure rate limiting unconditionally**: Make Traefik (or equivalent) rate limiting a required deployment constraint, not an optional Helm value.
4. **Alert on request volume alongside latency**: Prometheus alerting rules should correlate p99 latency spikes with abnormal request-rate increases to distinguish genuine degradation from metric flooding.

### Proof of Concept
```bash
# Flood the transactions endpoint from a single unprivileged client
# No credentials required
for i in $(seq 1 5000); do
  curl -s "http://<mirror-node-host>:5551/api/v1/transactions?account.id=0.0.1234" &
done
wait

# After ~15–30 seconds, scrape the metrics endpoint (if accessible or via Prometheus)
curl -u mirror_api_metrics:mirror_api_metrics_pass \
  "http://<mirror-node-host>:5551/swagger/metrics/"

# Observe api_request_duration_milliseconds_bucket for path="/api/v1/transactions"
# p99 will be inflated into the highest bucket (>500ms) due to server load
# Prometheus alerting rules on histogram_quantile(0.99, ...) will fire
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/middleware/metricsHandler.js (L91-95)
```javascript
  durationHistogram = meter.createHistogram('api_request_duration_milliseconds', {
    description: 'Request duration in milliseconds',
    unit: 'ms',
    advice: {explicitBucketBoundaries: durationBuckets},
  });
```

**File:** rest/middleware/metricsHandler.js (L167-169)
```javascript
    // Instrument all other requests
    const startTime = Date.now();
    inFlightCounter.add(1);
```

**File:** rest/middleware/metricsHandler.js (L185-210)
```javascript
    res.on('finish', () => {
      inFlightCounter.add(-1);

      const duration = Date.now() - startTime;
      const path = toOpenApiPath(req, res);
      const code = String(res.statusCode);
      const method = req.method;
      const labels = {method, path, code};

      // Aggregate counters
      allRequestCounter.add(1);
      if (res.statusCode >= 200 && res.statusCode < 300) {
        allSuccessCounter.add(1);
      } else if (res.statusCode >= 400 && res.statusCode < 500) {
        allClientErrorCounter.add(1);
        allErrorCounter.add(1);
      } else if (res.statusCode >= 500) {
        allServerErrorCounter.add(1);
        allErrorCounter.add(1);
      }

      // Per-route metrics
      requestTotalCounter.add(1, labels);
      durationHistogram.record(duration, labels);
      requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
      responseSizeHistogram.record(responseSize, labels);
```

**File:** rest/server.js (L85-92)
```javascript
// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```
