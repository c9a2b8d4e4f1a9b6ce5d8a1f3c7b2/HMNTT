### Title
Unbounded Duration Recording in `metricsMiddleware` Enables Histogram Inflation via Unauthenticated Slow Requests

### Summary
The `metricsMiddleware()` function in `rest/middleware/metricsHandler.js` records the raw wall-clock duration of every request into `durationHistogram` with no upper-bound cap, no per-IP rate limiting, and no server-side request timeout. An unprivileged attacker can flood Hashgraph history endpoints (e.g., `/api/v1/transactions`) with crafted timestamp-range queries that cause expensive database scans, artificially inflating the per-route histogram and triggering false-positive latency alerts while a real tampering attack proceeds undetected on other endpoints.

### Finding Description
**Exact code path:**

In `rest/middleware/metricsHandler.js`, `metricsMiddleware()`:

- Line 168: `const startTime = Date.now();` — wall-clock timer starts unconditionally for every unauthenticated request.
- Line 188: `const duration = Date.now() - startTime;` — raw elapsed time, no cap.
- Line 208: `durationHistogram.record(duration, labels);` — unbounded value written into the per-route histogram with labels `{method, path, code}`.

**Root cause / failed assumption:** The middleware assumes that request durations are bounded by normal operational behavior. It applies no maximum duration clamp before recording, and the surrounding server stack (`rest/server.js` lines 88–92) installs no rate-limiting middleware and configures no HTTP-level `server.timeout`. The `limit` query parameter is capped at `responseLimit.max` (lines 544–552 of `rest/utils.js`), but this only restricts result-set rows — it does not prevent wide timestamp-range predicates from causing full-table or cross-partition scans that run for seconds.

**Why existing checks fail:**
- `authHandler` (line 86 of `server.js`) only sets a custom row limit for authenticated users; unauthenticated requests pass through freely.
- `responseCacheCheckHandler` (line 97) short-circuits only cache hits; a cache miss (e.g., a unique timestamp range per request) falls through to the full DB query.
- No `express-rate-limit`, no `connect-timeout`, and no `pg` statement timeout is visible in the REST middleware chain.

### Impact Explanation
An attacker who successfully inflates `api_request_duration_milliseconds` for the `/api/v1/transactions` (or similar history) route causes Prometheus/Alertmanager rules keyed on p95/p99 latency to fire false-positive pages. Operators are drawn into investigating a phantom latency regression on history endpoints while a real integrity attack (e.g., injected or replayed records) proceeds on a different endpoint whose metrics remain quiet. The histogram is cumulative and monotonically increasing within a scrape window, so even a modest sustained flood (tens of requests per second) permanently shifts bucket counts upward for the duration of the attack.

### Likelihood Explanation
No privileges are required. The attacker needs only network access to the REST API and knowledge of a timestamp range that misses the cache (trivially achieved by using `timestamp=gt:<recent_ns>` with a unique nanosecond boundary per request). The attack is fully repeatable, scriptable with `curl` or any HTTP client, and requires no authentication, no special headers, and no exploitation of memory-safety bugs.

### Recommendation
1. **Clamp recorded duration**: Before calling `durationHistogram.record()`, apply `Math.min(duration, MAX_DURATION_MS)` where `MAX_DURATION_MS` matches the configured server timeout, preventing outlier values from distorting bucket counts.
2. **Enforce a server-side request timeout**: Set `server.timeout` and `server.requestTimeout` on the Node.js HTTP server, and add a `pg` `statement_timeout` on the database pool so slow queries are killed before they complete.
3. **Add rate limiting**: Install `express-rate-limit` (or equivalent) before `metricsHandler` in `server.js` to bound the rate at which any single IP can contribute samples to the histogram.
4. **Separate alert signal from raw histogram**: Alert on the rate of change of high-latency buckets rather than absolute bucket counts, making a sudden flood of slow requests distinguishable from a genuine latency regression.

### Proof of Concept
```bash
# Flood the transactions endpoint with unique timestamp ranges (cache misses)
# Each request triggers a full DB scan and records a high duration sample
for i in $(seq 1 500); do
  curl -s "http://<mirror-node>/api/v1/transactions?timestamp=gt:$((1600000000 + i * 1000000000))&timestamp=lt:$((1700000000 + i * 1000000000))&limit=1" &
done
wait

# Scrape metrics and observe inflated p99 for the transactions route
curl http://<mirror-node>/api/v1/metrics/ | grep api_request_duration_milliseconds
# Expected: bucket counts for ">500ms" bucket on path=/api/v1/transactions are
# orders of magnitude higher than baseline, triggering latency alert rules.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/middleware/metricsHandler.js (L168-168)
```javascript
    const startTime = Date.now();
```

**File:** rest/middleware/metricsHandler.js (L185-208)
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
```

**File:** rest/server.js (L88-92)
```javascript
// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```

**File:** rest/utils.js (L544-553)
```javascript
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
```
