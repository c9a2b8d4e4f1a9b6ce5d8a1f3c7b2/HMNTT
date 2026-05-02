### Title
Metrics Label Injection via Unvalidated `req.path` in `toOpenApiPath()` Enables Prometheus Cardinality Explosion

### Summary
The `toOpenApiPath()` function in `rest/middleware/metricsHandler.js` uses `req.path` directly as a Prometheus metric label when no route matches a request. The only guard — a `startsWith(apiPrefix)` check — does not validate that the path corresponds to a known route, allowing any unprivileged attacker to inject arbitrary label values into per-route counters and histograms, including paths like `/api/v1/api/v1/transactions` that superficially resemble valid routes. Repeated requests with unique paths cause cardinality explosion, exhausting Prometheus memory and degrading monitoring infrastructure.

### Finding Description

**Exact code path:**

`toOpenApiPath()` at [1](#0-0) 

```
path = req.path;                          // line 18 — user-controlled
path = path.replace(/:([^/]+)/g, '{$1}'); // line 24 — no sanitization
if (!path.startsWith(apiPrefix)) {        // line 26 — only prefix check
  return apiPrefix + '/' + path;
}
return path;                              // line 30 — returned as-is
```

The result is used as a Prometheus label at: [2](#0-1) 

**Root cause:** When a request matches no registered route, `res.locals[requestPathLabel]` is never set (the `responseHandler` throws `NotFoundError` instead of populating it — [3](#0-2) ) and `req.route` is `null`. The fallback `path = req.path` is entirely user-controlled. The `startsWith('/api/v1')` guard only decides whether to prepend the prefix; it performs no validation against the set of registered routes.

**Exploit flow for `/api/v1/api/v1/transactions`:**
1. `res.locals[requestPathLabel]` → not set (no route matched)
2. `req.route` → `null` (no route matched)
3. `path = req.path` → `/api/v1/api/v1/transactions`
4. Regex replace → no change (no `:param` segments)
5. `path.startsWith('/api/v1')` → `true` → returned as-is
6. `requestTotalCounter.add(1, {method, path: '/api/v1/api/v1/transactions', code})` — phantom label injected

**Why the check fails:** `apiPrefix = '/api/v1'` [4](#0-3)  — the `startsWith` test is satisfied by any path beginning with that string, including crafted ones with repeated segments or arbitrary suffixes.

### Impact Explanation
Prometheus stores one time-series per unique label combination. Each unique `path` value injected by an attacker creates new time-series for `api_request_total`, `api_request_duration_milliseconds`, `api_request_size_bytes`, and `api_response_size_bytes`. Sending thousands of requests with distinct paths (e.g., `/api/v1/<uuid>`) causes cardinality explosion, exhausting Prometheus heap memory and potentially crashing the scrape target or the Prometheus server itself. This is a DoS against the monitoring plane. Additionally, phantom routes like `/api/v1/api/v1/transactions` pollute dashboards and alerting rules that rely on the `path` label to detect anomalies in real transaction endpoints.

### Likelihood Explanation
No authentication is required. The metrics middleware is registered globally for all requests: [5](#0-4)  Any HTTP client can trigger this. The attack is trivially scriptable — a loop sending GET requests with unique path suffixes is sufficient. The server returns 404 for each, but the `res.on('finish')` callback still fires and records the label. [6](#0-5) 

### Recommendation
Replace the raw `req.path` fallback with a fixed sentinel label for unmatched routes:

```js
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];

  if (!path) {
    if (!req.route) {
      // Do NOT use req.path — it is user-controlled and causes label injection.
      return `${apiPrefix}/unknown`;
    }
    path = (req.baseUrl ?? '') + req.route?.path;
  }

  path = path.replace(/:([^/]+)/g, '{$1}');

  if (!path.startsWith(apiPrefix)) {
    return `${apiPrefix}/${path}`;
  }

  return path;
};
```

This collapses all unmatched requests into a single `path="/api/v1/unknown"` label, eliminating cardinality explosion while preserving useful aggregate counts.

### Proof of Concept

```bash
# Single phantom-route injection
curl -s http://<mirror-node-host>/api/v1/api/v1/transactions
# → 404 response, but Prometheus now has a time-series for
#   path="/api/v1/api/v1/transactions"

# Cardinality explosion (run in a loop)
for i in $(seq 1 5000); do
  curl -s "http://<mirror-node-host>/api/v1/$(uuidgen)" &
done
wait

# Verify injected labels in Prometheus
curl http://<prometheus-host>/api/v1/label/path/values | jq '.data | length'
# Returns 5000+ unique path values instead of the ~20 legitimate routes
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

**File:** rest/middleware/metricsHandler.js (L185-211)
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
    });
```

**File:** rest/middleware/responseHandler.js (L28-31)
```javascript
  if (responseData === undefined) {
    // unmatched route will have no response data, pass NotFoundError to next middleware
    throw new NotFoundError();
  }
```

**File:** rest/constants.js (L19-19)
```javascript
const apiPrefix = '/api/v1';
```

**File:** rest/server.js (L89-92)
```javascript
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
