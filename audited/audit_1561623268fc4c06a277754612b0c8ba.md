### Title
Unauthenticated `content-length` Header Injection Poisons `api_request_size_bytes` Histogram Overflow Bucket

### Summary
In `rest/middleware/metricsHandler.js`, the `metricsMiddleware()` function reads `req.headers['content-length']` directly and passes the parsed integer to `requestSizeHistogram.record()` with no upper-bound validation. Any unauthenticated caller can set `content-length: 2147483648` (or any value exceeding the OpenTelemetry default bucket ceiling of 10000) to force every such observation into the `+Inf` overflow bucket, permanently degrading the `api_request_size_bytes` histogram's usefulness for percentile calculations.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, line 209 (inside the `res.on('finish', ...)` callback of `metricsMiddleware`):
```js
requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
```

**Root cause — failed assumption:**
The code assumes the `content-length` header reflects a realistic body size. There is no upper-bound clamp. The only guard (`|| 0`) only handles `NaN`/falsy; it passes any positive integer, including `2147483648`.

**Histogram bucket configuration:**
`requestSizeBuckets` defaults to `[]` (line 58):
```js
requestSizeBuckets = [],
```
When `advice: {explicitBucketBoundaries: []}` is passed to the OpenTelemetry JS SDK (line 99), the SDK falls back to its built-in default boundaries:
`[0, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000]`.
A recorded value of `2147483648` exceeds the highest boundary (`10000`) and is counted exclusively in the `+Inf` overflow bucket.

**Exploit flow:**
1. Attacker sends `GET /api/v1/accounts` with header `content-length: 2147483648` (no body required).
2. Express processes the request normally; the `finish` event fires.
3. `parseInt('2147483648', 10)` → `2147483648`; the `|| 0` guard does not trigger.
4. `requestSizeHistogram.record(2147483648, labels)` is called.
5. The value exceeds all bucket boundaries → recorded in `+Inf` only.
6. Repeated at scale, all observations accumulate in `+Inf`; no finite bucket receives counts; `histogram_quantile` in Prometheus returns `+Inf` for all percentiles.

**Why existing checks fail:**
- `|| 0` only catches `NaN` and `0`; it does not cap large integers.
- There is no cross-check against the actual received body size.
- There is no rate-limit or per-IP throttle on the metrics recording path.
- The `finish` event fires for every request regardless of HTTP status code, including 400-level rejections where the body was never read.

### Impact Explanation
The `api_request_size_bytes` histogram (metric name `api_request_size_bytes_bucket`) is used by the Grafana dashboard to visualise request-size distribution. Once the overflow bucket dominates, `histogram_quantile(0.95, ...)` and similar PromQL expressions return `+Inf`, making SLO/SLA alerting on request size meaningless. Operators lose the ability to detect abnormally large payloads or capacity trends. The impact is limited to observability degradation (griefing); no user data is exposed and no service availability is affected.

### Likelihood Explanation
The attack requires zero privileges — any HTTP client reachable to the public API endpoint can set arbitrary headers. It is trivially scriptable with a single `curl` invocation and is repeatable at any rate the attacker can sustain HTTP connections. No authentication, no special network position, and no knowledge of internal state is required.

### Recommendation
1. **Clamp the recorded value** to a sane maximum before calling `record()`:
   ```js
   const MAX_RECORDED_BYTES = 10_000_000; // 10 MB, adjust to match server body limit
   const rawLen = parseInt(req.headers['content-length'] ?? '0', 10);
   const clampedLen = Number.isFinite(rawLen) && rawLen > 0
     ? Math.min(rawLen, MAX_RECORDED_BYTES)
     : 0;
   requestSizeHistogram.record(clampedLen, labels);
   ```
2. **Alternatively, measure the actual body bytes** rather than trusting the header (e.g., accumulate bytes in a `data` event listener, similar to how `responseSize` is measured via `res.write`/`res.end` interception).
3. **Set explicit, meaningful `requestSizeBuckets`** in the default configuration (e.g., `[100, 1000, 10000, 100000, 1000000]`) so that even without clamping the bucket structure is appropriate for the expected payload range.

### Proof of Concept
```bash
# Single poisoning request — no body needed
curl -s -o /dev/null \
  -H "content-length: 2147483648" \
  "http://<mirror-node-rest>:5551/api/v1/accounts"

# Verify histogram is poisoned — all counts in +Inf bucket
curl -s "http://<mirror-node-rest>:5551/swagger/metrics/" \
  -u mirror_api_metrics:mirror_api_metrics_pass \
  | grep 'api_request_size_bytes_bucket.*le="+Inf"'
# Expected: counter increments only in the +Inf bucket; all finite le= buckets remain at 0
```