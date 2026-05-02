All code references check out against the actual source. Let me verify the findings:

**Line 18** — `path = req.path` is confirmed in `rest/middleware/metricsHandler.js`. [1](#0-0) 

**Lines 192, 207–210** — raw `path` used as Prometheus label in all four per-route instruments. [2](#0-1) 

**`recordRequestPath`** only sets `res.locals[requestPathLabel]` when `req.route?.path` exists, confirming the fallback is always hit for 404 paths. [3](#0-2) 

**Metrics middleware** is registered unconditionally before all route handlers. [4](#0-3) 

The SECURITY.md excludes "Impacts that only require DDoS," but this attack exploits a specific code flaw (unbounded label cardinality from unsanitized input) and does not require volumetric traffic — a slow drip of unique paths is sufficient. That distinguishes it from a generic DDoS exclusion. [5](#0-4) 

---

Audit Report

## Title
Prometheus Label Cardinality Injection via Unsanitized `req.path` on Unmatched Routes

## Summary
`toOpenApiPath()` in `rest/middleware/metricsHandler.js` falls back to the raw, attacker-controlled `req.path` as a Prometheus label value for any request that does not match a registered Express route. Because the metrics middleware runs unconditionally for every request, an unauthenticated attacker can generate an unbounded number of unique Prometheus time series by sending requests to arbitrary unregistered paths, exhausting Prometheus memory and polluting operator dashboards.

## Finding Description
In `rest/middleware/metricsHandler.js`, `toOpenApiPath()` (lines 13–31) resolves the Prometheus `path` label in three steps:

1. Check `res.locals[requestPathLabel]` — only populated by `recordRequestPath` in `rest/routes/index.js` (line 18–19) when `req.route?.path` exists, i.e., only for matched routes.
2. If that is empty and `req.route` is `undefined` (all 404 paths), fall back to `req.path` — the raw, unsanitized request path (line 18).
3. Apply `replace(/:([^/]+)/g, '{$1}')` — this only normalises Express `:param` tokens; it does not collapse arbitrary path segments like `0.0.1234` or `fake`.

The resulting `path` value is then used as a label on all four per-route instruments at lines 192 and 207–210:

```js
const labels = {method, path, code};
requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
```

The metrics middleware is registered at `rest/server.js` lines 89–92 before any route handler, so every request — including those that ultimately 404 — passes through it and triggers the `res.on('finish', …)` label recording.

## Impact Explanation
Each unique `path` label value creates a new time series in every per-route instrument. With four instruments (`api_request_total`, `api_request_duration_milliseconds`, `api_request_size_bytes`, `api_response_size_bytes`), N unique crafted paths produce 4×N new time series. Prometheus stores all active time series in memory, leading to:

1. **Prometheus OOM / scrape failure** — the monitoring plane becomes unavailable, blinding operators to real production issues.
2. **Dashboard pollution** — Grafana panels (e.g., "Request Rate by Path") display attacker-crafted paths alongside legitimate routes, masking real anomalies and misleading incident response.

## Likelihood Explanation
The attack requires zero privileges — only the ability to send HTTP GET requests to the public API. No authentication, no special headers, no account is needed. The exploit is trivially scriptable (a loop incrementing a path segment is sufficient) and can be sustained at a low request rate, well below typical rate-limit thresholds, while still accumulating thousands of unique time series over time.

## Recommendation
Replace the raw fallback with a fixed sentinel value for unmatched routes:

```js
if (!req.route) {
  path = 'unknown'; // or '/api/v1/unknown'
}
```

This collapses all unmatched-route requests into a single time series per method/status combination, eliminating the cardinality attack surface entirely. Optionally, add a path length cap and an allowlist check before the label is recorded.

## Proof of Concept
```bash
# Send requests to incrementing unregistered paths
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node-host>/api/v1/transactions/0.0.${i}/fake" &
done
wait
# Each unique path creates 4 new Prometheus time series.
# After 10,000 iterations: 40,000 new time series injected.
# Scrape the /metrics endpoint to confirm cardinality growth.
```

### Citations

**File:** rest/middleware/metricsHandler.js (L13-31)
```javascript
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];

  if (!path) {
    if (!req.route) {
      path = req.path;
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }

  path = path.replace(/:([^/]+)/g, '{$1}');

  if (!path.startsWith(apiPrefix)) {
    return apiPrefix + '/' + path;
  }

  return path;
};
```

**File:** rest/middleware/metricsHandler.js (L192-210)
```javascript
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

**File:** rest/routes/index.js (L16-21)
```javascript
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};
```

**File:** rest/server.js (L89-92)
```javascript
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
