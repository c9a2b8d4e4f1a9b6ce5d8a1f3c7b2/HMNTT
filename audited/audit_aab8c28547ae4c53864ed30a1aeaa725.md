### Title
Unauthenticated Metrics Endpoint Lacks Rate Limiting, Enabling CPU-Exhaustion Griefing via Concurrent Scrape Flooding

### Summary
When `config.metrics.config.authentication` is `false`, the `metricsMiddleware` function in `rest/middleware/metricsHandler.js` allows any unauthenticated caller to trigger `exporter.collect()` and the synchronous `serializer.serialize(resourceMetrics)` on every request with no rate limiting, concurrency cap, or response caching. An attacker flooding this endpoint with concurrent requests forces repeated execution of CPU-bound serialization on Node.js's single-threaded event loop, degrading response latency for all other API consumers.

### Finding Description
**Exact code path:**

In `rest/middleware/metricsHandler.js`, the `authenticate()` function short-circuits to `return true` when `authentication` is falsy: [1](#0-0) 

Every request matching `metricsPath` then unconditionally executes: [2](#0-1) 

`exporter.collect()` fires all registered observable gauge callbacks — including `process.cpuUsage()`, `process.hrtime.bigint()`, and `process.memoryUsage()` — on every call: [3](#0-2) 

`serializer.serialize(resourceMetrics)` is a synchronous, CPU-bound operation (PrometheusSerializer iterates all metric data points and builds a text string). Because Node.js is single-threaded, concurrent `serialize()` calls queue up on the event loop.

**Root cause:** No rate limiting, no in-flight concurrency cap, and no cached-response TTL exist anywhere in the middleware stack for this endpoint. The server-level middleware chain confirms no rate limiter is applied: [4](#0-3) 

**Why existing checks fail:** The only guard is `authenticate()`. With `authentication = false` it is a no-op. There is no `express-rate-limit`, semaphore, or last-scrape cache anywhere in `rest/middleware/metricsHandler.js` or `rest/server.js`.

### Impact Explanation
An attacker sending N concurrent GET requests to `/swagger/metrics/` causes N simultaneous `serialize()` executions to be queued on the event loop. Because `serialize()` is synchronous and CPU-bound, the event loop stalls proportionally, increasing p99 latency for every other in-flight API request (accounts, transactions, tokens, etc.). The impact is service degradation (griefing) with no economic damage to the network itself — consistent with the Medium classification.

### Likelihood Explanation
Preconditions are minimal: the attacker needs network access to the REST API port and knowledge of the metrics path (default `/swagger/metrics/`, documented in `docs/configuration.md`). No credentials, tokens, or special privileges are required when `authentication = false`. The attack is trivially repeatable with a single `ab` or `wrk` command and requires no prior state. [5](#0-4) 

### Recommendation
Apply at least one of the following mitigations directly in `metricsMiddleware`:

1. **Response caching with TTL**: Cache the last serialized output and serve it for subsequent requests within a configurable window (e.g., 5 s), so `collect()` + `serialize()` run at most once per interval regardless of request rate.
2. **In-flight concurrency guard**: Track an `isCollecting` boolean; if a collection is already in progress, queue or reject the new request rather than spawning a parallel one.
3. **Rate limiting**: Apply `express-rate-limit` (or equivalent) specifically to the metrics path before the `collect()` call.
4. **Default `authentication` to `true`**: Change the default configuration so authentication is opt-out rather than opt-in, reducing the attack surface for misconfigured deployments.

### Proof of Concept
**Preconditions:** Mirror Node REST API running with `config.metrics.enabled = true` and `config.metrics.config.authentication = false` (or unset).

```bash
# Step 1 – confirm endpoint is open
curl -s http://<host>:5551/swagger/metrics/ | head -5

# Step 2 – flood with 500 concurrent requests, 5000 total
ab -n 5000 -c 500 http://<host>:5551/swagger/metrics/

# Step 3 – observe degraded latency on a normal API endpoint during the flood
while true; do
  time curl -s http://<host>:5551/api/v1/transactions?limit=1 > /dev/null
  sleep 0.1
done
```

**Expected result:** p99 latency on `/api/v1/transactions` increases measurably during the flood as the event loop is saturated by concurrent synchronous `serialize()` calls, while the metrics endpoint itself returns 200 for every request with no throttling applied.

### Citations

**File:** rest/middleware/metricsHandler.js (L115-123)
```javascript
    .addCallback((result) => {
      const currentCpuUsage = process.cpuUsage();
      const currentHrTime = process.hrtime.bigint();
      const elapsedUs = Number(currentHrTime - previousHrTime) / 1000;
      const cpuUs = currentCpuUsage.user - previousCpuUsage.user + (currentCpuUsage.system - previousCpuUsage.system);
      previousCpuUsage = currentCpuUsage;
      previousHrTime = currentHrTime;
      result.observe(elapsedUs > 0 ? (cpuUs / elapsedUs) * 100 : 0);
    });
```

**File:** rest/middleware/metricsHandler.js (L137-144)
```javascript
const authenticate = (req) => {
  const {authentication, username, password} = config.metrics.config;
  if (!authentication) {
    return true;
  }
  const credentials = basicAuth(req);
  return credentials && tsscmp(credentials.name, username) && tsscmp(credentials.pass, password);
};
```

**File:** rest/middleware/metricsHandler.js (L161-164)
```javascript
      return exporter.collect().then(({resourceMetrics}) => {
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.send(serializer.serialize(resourceMetrics));
      });
```

**File:** rest/server.js (L88-92)
```javascript
// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```

**File:** docs/configuration.md (L571-573)
```markdown
| `hiero.mirror.rest.metrics.config.password`                              | mirror_api_metrics_pass | The REST API metrics password to access the dashboard                                                                                                                                         |
| `hiero.mirror.rest.metrics.config.uriPath`                               | '/swagger'              | The REST API metrics uri path                                                                                                                                                                 |
| `hiero.mirror.rest.metrics.enabled`                                      | true                    | Whether metrics should be collected and exposed for scraping                                                                                                                                  |
```
