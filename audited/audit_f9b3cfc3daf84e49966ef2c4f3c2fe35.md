### Title
Unauthenticated Metrics Endpoint Flooding Enables Event Loop Exhaustion via Unbounded `exporter.collect()` Invocations

### Summary
When `config.metrics.config.authentication` is falsy (the default when not explicitly configured), the `authenticate()` function unconditionally returns `true`, granting any unauthenticated external caller full access to the metrics endpoint. There is no rate limiting, concurrency cap, or request queuing on this path, so a flood of concurrent requests causes `exporter.collect()` — including its observable gauge callbacks for CPU and memory — to execute without bound, saturating the Node.js event loop and degrading all API response latency, including block-related queries.

### Finding Description
**Code path:**

`rest/middleware/metricsHandler.js`, `authenticate()` lines 137–144:
```js
const authenticate = (req) => {
  const {authentication, username, password} = config.metrics.config;
  if (!authentication) {
    return true;          // ← any caller passes when auth is not configured
  }
  ...
};
``` [1](#0-0) 

`metricsMiddleware` lines 156–164 — once `authenticate()` returns `true`, `exporter.collect()` is called with no guard:
```js
if (normalizedPath === metricsPath) {
  if (!authenticate(req)) { ... return 401; }
  return exporter.collect().then(({resourceMetrics}) => {   // ← no concurrency limit
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.send(serializer.serialize(resourceMetrics));
  });
}
``` [2](#0-1) 

`exporter.collect()` fires every registered observable-gauge callback on each invocation, including the CPU-usage gauge that calls `process.cpuUsage()` and `process.hrtime.bigint()`, and four memory gauges that call `process.memoryUsage()`: [3](#0-2) 

The metrics middleware is registered globally with no preceding rate-limit middleware: [4](#0-3) 

**Root cause:** The failed assumption is that `authentication` will always be explicitly set to `true` in production. In practice, when the key is absent from config, it is `undefined` (falsy), so the guard is silently bypassed. No rate-limiting or concurrency-control layer exists anywhere in the `rest/` middleware stack for this path.

### Impact Explanation
Node.js runs on a single-threaded event loop. Each unauthenticated GET to the metrics path enqueues a `exporter.collect()` microtask chain plus `PrometheusSerializer.serialize()` CPU work. Under a sustained flood (e.g., thousands of requests/second from a single host), the event loop queue grows unboundedly, increasing latency for all other in-flight requests — including `/api/v1/blocks`, `/api/v1/transactions`, and health-check endpoints. Sustained saturation can cause the liveness probe to time out, triggering a container restart and a brief window where block-acknowledgment queries are unavailable. The metrics response body also grows with the number of registered label combinations, amplifying serialization cost per request.

### Likelihood Explanation
Precondition: `authentication` is not set (the default — no default config YAML was found in the repository that sets it to `true`). The attacker needs only network access to the REST API port and knowledge of the metrics path (derivable from `config.metrics.config.uriPath`, defaulting to a well-known path). No credentials, tokens, or special privileges are required. The attack is trivially repeatable with any HTTP load tool (`wrk`, `ab`, `curl` in a loop).

### Recommendation
1. **Default-deny:** Change the `authenticate()` guard so that the absence of an `authentication` key is treated as `false` (deny), not `true` (allow). Require operators to explicitly opt out of authentication.
2. **Rate-limit the metrics path:** Add a per-IP rate limiter (e.g., `express-rate-limit`) specifically for the metrics route before `exporter.collect()` is called.
3. **Concurrency cap:** Use a semaphore or a cached/debounced collect result (e.g., cache the last scrape for 5 seconds) so that concurrent requests do not each trigger a full collection cycle.
4. **Network-level restriction:** Document and enforce that the metrics path should only be reachable from internal/monitoring networks, not the public internet.

### Proof of Concept
```bash
# Precondition: metrics.config.authentication is not set (default)
# Metrics path assumed to be /swagger/metrics/ (default uriPath=/swagger)

# Flood with 500 concurrent connections, 100k total requests
wrk -t8 -c500 -d60s http://<mirror-node-rest-host>:<port>/swagger/metrics/

# Observable effect: p99 latency on /api/v1/blocks rises sharply;
# health check at /health/liveness begins timing out under sustained load.
```

No credentials are supplied. Every request passes `authenticate()` and triggers `exporter.collect()` + `PrometheusSerializer.serialize()` on the Node.js event loop.

### Citations

**File:** rest/middleware/metricsHandler.js (L111-134)
```javascript
  meter
    .createObservableGauge('nodejs_process_cpu_usage_percentage', {
      description: 'Process CPU usage percentage',
    })
    .addCallback((result) => {
      const currentCpuUsage = process.cpuUsage();
      const currentHrTime = process.hrtime.bigint();
      const elapsedUs = Number(currentHrTime - previousHrTime) / 1000;
      const cpuUs = currentCpuUsage.user - previousCpuUsage.user + (currentCpuUsage.system - previousCpuUsage.system);
      previousCpuUsage = currentCpuUsage;
      previousHrTime = currentHrTime;
      result.observe(elapsedUs > 0 ? (cpuUs / elapsedUs) * 100 : 0);
    });

  for (const [name, key] of [
    ['nodejs_process_memory_rss_bytes', 'rss'],
    ['nodejs_process_memory_heap_total_bytes', 'heapTotal'],
    ['nodejs_process_memory_heap_used_bytes', 'heapUsed'],
    ['nodejs_process_memory_external_bytes', 'external'],
  ]) {
    meter.createObservableGauge(name, {unit: 'By'}).addCallback((result) => {
      result.observe(process.memoryUsage()[key]);
    });
  }
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

**File:** rest/middleware/metricsHandler.js (L156-165)
```javascript
    if (normalizedPath === metricsPath) {
      if (!authenticate(req)) {
        res.set('WWW-Authenticate', 'Basic realm="Metrics"');
        return res.status(401).send('Unauthorized');
      }
      return exporter.collect().then(({resourceMetrics}) => {
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.send(serializer.serialize(resourceMetrics));
      });
    }
```

**File:** rest/server.js (L88-92)
```javascript
// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
