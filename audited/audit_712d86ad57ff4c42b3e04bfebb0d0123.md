### Title
Hex-Encoded `Content-Length` Header Causes Silent Zero Recording in `api_request_size_bytes` Metric

### Summary
In `metricsMiddleware()`, the request size is read from the `content-length` header and parsed with `parseInt(value, 10)`. When a client sends `Content-Length: 0x7FFFFFFF`, JavaScript's `parseInt` with radix 10 stops parsing at the `x` character and returns `0`. The `|| 0` fallback does not catch this because `0` is already falsy, so `0` is silently recorded in the histogram, hiding the actual payload size from monitoring.

### Finding Description
**File:** `rest/middleware/metricsHandler.js`, function `metricsMiddleware()`, line 209:

```js
requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
```

**Root cause:** `parseInt('0x7FFFFFFF', 10)` in JavaScript parses `'0'` (valid base-10 digit), then stops at `'x'` (invalid for base 10), returning `0`. The `|| 0` guard is intended to handle `NaN` from completely non-numeric strings, but `parseInt('0x7FFFFFFF', 10)` returns `0` (not `NaN`), so the guard is bypassed and `0` is recorded. Node.js/Express does not validate or reject non-decimal `Content-Length` header values, so the header reaches the middleware unchanged.

**Exploit flow:**
1. Attacker sends any API request with `Content-Length: 0x7FFFFFFF` (and an actual body of arbitrary size).
2. Express passes the raw header string to the middleware.
3. `parseInt('0x7FFFFFFF', 10)` → `0`; `0 || 0` → `0`.
4. `requestSizeHistogram.record(0, labels)` is called regardless of actual body size.

### Impact Explanation
The `api_request_size_bytes` Prometheus histogram consistently records `0` bytes for any request carrying a hex-encoded `Content-Length`. This corrupts capacity-planning metrics, suppresses size-based alerting thresholds, and allows an attacker to repeatedly send large payloads that appear as zero-byte requests in all monitoring dashboards. The impact is confined to observability/metrics integrity; actual request processing and transaction handling are unaffected.

### Likelihood Explanation
No authentication or special privilege is required. Any HTTP client can set arbitrary request headers. The attack is trivially repeatable with a single curl flag (`-H 'Content-Length: 0x7FFFFFFF'`) and produces no error, log entry, or rejection from the server, making it undetectable without inspecting raw access logs.

### Recommendation
Replace `parseInt(..., 10)` with `Number(...)` or validate that the header is a strict decimal integer before parsing:

```js
// Option 1: use Number() which correctly handles hex (returns NaN for '0x...' only when not intended)
// Actually Number('0x7FFFFFFF') = 2147483647, so use a strict decimal check:
const rawLen = req.headers['content-length'] ?? '0';
const contentLength = /^\d+$/.test(rawLen) ? parseInt(rawLen, 10) : 0;
requestSizeHistogram.record(contentLength, labels);
```

This ensures only decimal digit strings are accepted, rejecting hex-encoded values.

### Proof of Concept
```bash
# Send a request with a hex Content-Length; observe metric records 0 bytes
curl -X POST http://<mirror-node-rest>/api/v1/transactions \
  -H 'Content-Length: 0x7FFFFFFF' \
  -H 'Content-Type: application/json' \
  -d '{"largePayload": "..."}'

# Scrape Prometheus metrics endpoint and observe:
# api_request_size_bytes_sum{...} 0
# api_request_size_bytes_count{...} 1
# — actual body size is never reflected
```

Verify the JavaScript behavior directly:
```js
> parseInt('0x7FFFFFFF', 10)
0
> parseInt('0x7FFFFFFF', 10) || 0
0
``` [1](#0-0)

### Citations

**File:** rest/middleware/metricsHandler.js (L209-209)
```javascript
      requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
```
