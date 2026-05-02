### Title
Prometheus Label Cardinality Exhaustion via Unmatched Route Path Injection in `toOpenApiPath()`

### Summary
In `rest/middleware/metricsHandler.js`, the `toOpenApiPath()` function falls back to using `req.path` verbatim as a Prometheus label when `req.route` is undefined (i.e., no Express route matched the request). Because the `metricsMiddleware` instruments every request including 404s, an unauthenticated attacker can flood the server with requests to unique unmatched paths, injecting unbounded high-cardinality values into the `path` label of all per-route instruments. Once the OpenTelemetry SDK's default cardinality limit (~2000) is exhausted, new label combinations — including those for legitimate contract routes — are silently dropped.

### Finding Description
**Exact code path:**

In `rest/middleware/metricsHandler.js` lines 13–31, `toOpenApiPath()` resolves the path label:

```js
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];   // only set for matched routes

  if (!path) {
    if (!req.route) {
      path = req.path;                        // ← line 18: raw user-controlled path
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }
  path = path.replace(/:([^/]+)/g, '{$1}'); // no normalization for unmatched paths
  ...
};
```

`res.locals[requestPathLabel]` is only populated by `recordRequestPath` in `rest/routes/index.js` (lines 16–20), which only runs when `req.route?.path` is truthy — i.e., when a route actually matched. For any unmatched request, both `res.locals[requestPathLabel]` and `req.route` are `undefined`, so `req.path` is used as-is.

The `metricsMiddleware` (lines 185–211) hooks `res.on('finish', ...)` for **every** request, including 404s, and records the raw path into all four per-route instruments:

```js
const labels = {method, path, code};
requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
```

**Root cause:** No normalization, allowlist check, or length cap is applied to `req.path` before it becomes a Prometheus label. The `replace(/:([^/]+)/g, '{$1}')` transform only converts Express-style params and has no effect on arbitrary unmatched paths.

**Why existing checks fail:**
- `recordRequestPath` in `rest/routes/index.js` is registered only on matched routers (`AccountRoutes`, `BlockRoutes`, `ContractRoutes`). It never fires for unmatched paths.
- The contract routes in `rest/routes/contractRoute.js` (e.g., `/:contractId`, `/:contractId/results`) only match specific path structures. A path like `/api/v1/contracts/0xABC/nonexistent` does not match any registered route, leaving `req.route` undefined.
- There is no application-level cardinality guard before the OTel SDK's internal limit (~2000 unique attribute sets per instrument) is reached.

### Impact Explanation
Once the OTel SDK cardinality limit is exhausted across `requestTotalCounter`, `durationHistogram`, `requestSizeHistogram`, and `responseSizeHistogram`, new attribute combinations are silently dropped (overflow behavior). If the attacker pre-fills the cardinality budget with garbage paths before a node restart or before a new legitimate route is first observed, those legitimate route metrics are never recorded. Dashboards and alerts based on `api_request_total{path=...}` (as used in `charts/hedera-mirror-common/dashboards/hedera-mirror-rest.json`) become blind to specific contract routes. The API itself continues to function, but observability and SLA monitoring are silently degraded — a medium-severity impact consistent with the stated scope.

### Likelihood Explanation
No authentication or special privilege is required. Any HTTP client can send GET requests to arbitrary paths. Sending 2000 requests with unique paths (e.g., iterating a counter in the URL) is trivial with `curl`, `ab`, or a short script. The attack is repeatable after each process restart. Rate limiting, if present, slows but does not prevent the attack since the cardinality budget is small.

### Recommendation
1. **Normalize unmatched paths to a fixed sentinel label** instead of using `req.path` verbatim. For example:
   ```js
   if (!req.route) {
     path = 'unknown';  // or apiPrefix + '/unknown'
   }
   ```
2. Alternatively, **skip per-route metric recording entirely for unmatched routes** (they are already counted by the aggregate `allClientErrorCounter`/`allErrorCounter` counters which carry no `path` label).
3. If verbatim paths are needed for debugging, apply a **strict allowlist** against the set of known OpenAPI paths before using the value as a label.

### Proof of Concept
```bash
# Send 2500 requests to unique unmatched contract sub-paths (no auth needed)
for i in $(seq 1 2500); do
  curl -s "http://<mirror-node-rest>/api/v1/contracts/0x$(printf '%040x' $i)/nonexistent" &
done
wait

# Now query Prometheus — legitimate contract route metrics are absent or show overflow
curl http://<mirror-node-rest>/swagger/metrics/ | grep api_request_total
# Legitimate labels like path="/api/v1/contracts/{contractId}/results" will be missing
# or show no new increments after the cardinality limit was hit
```