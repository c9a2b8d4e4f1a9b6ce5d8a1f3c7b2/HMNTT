Looking at the actual code to verify all claims before rendering a verdict.

All four required checks pass against the actual code. Here is the verdict:

---

Audit Report

## Title
Unbounded `req.method` Used Verbatim as OpenTelemetry Label Enables Metrics Store Memory Griefing

## Summary
`metricsMiddleware()` in `rest/middleware/metricsHandler.js` reads `req.method` directly from the Express request object and uses it without any length check, allowlist, or truncation as the `method` dimension in the `{method, path, code}` label set recorded across four per-route OpenTelemetry instruments. Node.js's llhttp parser accepts arbitrary token strings as the HTTP method up to the default 16 KB header-size limit, so a request carrying a ~10,000-character method name reaches the middleware intact. An unauthenticated attacker can exploit this to inject arbitrarily large strings into the in-process OpenTelemetry attribute store.

## Finding Description
**Exact code path — `rest/middleware/metricsHandler.js`, function `metricsMiddleware`:**

```js
// line 191 – verbatim, no length check or allowlist
const method = req.method;
const labels = {method, path, code};   // line 192

requestTotalCounter.add(1, labels);                                          // line 207
durationHistogram.record(duration, labels);                                  // line 208
requestSizeHistogram.record(parseInt(req.headers['content-length']…), labels); // line 209
responseSizeHistogram.record(responseSize, labels);                          // line 210
``` [1](#0-0) [2](#0-1) 

**Root cause:** The code assumes `req.method` will always be a short, standard HTTP verb. No maximum-length guard, allowlist, or truncation is applied before the value is embedded in a label set.

**Why the HTTP layer does not block it:** Node.js's llhttp parser accepts any sequence of valid token characters as the method token up to `--max-http-header-size` (default 16,384 bytes). A 10,000-character method name fits comfortably within that budget and is delivered to Express as `req.method` verbatim.

**Why existing checks are insufficient:**

1. The OpenAPI validator is configured with `validateRequests: false`, so it performs no request-level validation and will not reject non-standard HTTP methods. [3](#0-2) 

2. The validator is also conditionally enabled only when `config.openapi.validation.enabled` is true or in test environments. [4](#0-3) 

3. No rate-limiting middleware is applied to general API routes anywhere in `rest/server.js`. [5](#0-4) 

4. The four instruments (`requestTotalCounter`, `durationHistogram`, `requestSizeHistogram`, `responseSizeHistogram`) each maintain their own independent cardinality budget in the OTel SDK. [6](#0-5) 

## Impact Explanation
The in-process Node.js metrics store retains all unique label sets for the lifetime of the process. The `@opentelemetry/sdk-metrics` SDK imposes a default cardinality cap of 2,000 attribute sets per instrument. With four instruments, an attacker can fill up to 2,000 × 4 = 8,000 label-set slots, each carrying a 10,000-character method string. The method strings alone account for roughly **80 MB of heap strings** (8,000 × 10,000 bytes), not counting surrounding OTel attribute-map objects. This constitutes a bounded but meaningful heap inflation that can degrade garbage-collection performance, increase memory pressure, and—on memory-constrained deployments—trigger OOM restarts. No authentication or privilege is required.

## Likelihood Explanation
The attack requires only the ability to send HTTP requests to the public REST API, which is the intended use of the service. No credentials, tokens, or special network position are needed. The exploit is trivially scriptable: a single loop sending requests with a long method string to each known API path exhausts the cardinality budget rapidly. It is fully repeatable after a process restart. The `metricsHandler` fires on every `res.finish` event regardless of whether a route matched, so even 404 responses contribute to label-set accumulation. [7](#0-6) 

## Recommendation
Apply one or more of the following mitigations in `metricsMiddleware`:

1. **Allowlist standard HTTP verbs** before constructing the label set:
   ```js
   const ALLOWED_METHODS = new Set(['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS']);
   const method = ALLOWED_METHODS.has(req.method) ? req.method : 'UNKNOWN';
   ```
2. **Truncate to a safe maximum length** (e.g., 16 characters) as a defence-in-depth fallback:
   ```js
   const method = (req.method ?? '').slice(0, 16).toUpperCase();
   ```
3. **Enable request validation** in the OpenAPI validator (`validateRequests: true`) so non-standard methods are rejected at the middleware layer before reaching metrics instrumentation. [8](#0-7) 

## Proof of Concept
```bash
# Generate a 10,000-character method name
METHOD=$(python3 -c "print('A'*10000)")

# Send to each known API path to vary the 'path' label dimension
for PATH in /api/v1/accounts /api/v1/balances /api/v1/transactions \
            /api/v1/tokens /api/v1/schedules /api/v1/blocks; do
  curl -s -X "$METHOD" "http://<target>$PATH" &
done
wait

# Repeat until cardinality cap (2,000 per instrument) is reached.
# Each iteration inserts a 10,000-byte string into 4 OTel instruments.
# Total heap inflation: ~80 MB of retained label strings.
```

### Citations

**File:** rest/middleware/metricsHandler.js (L87-105)
```javascript
  // --- Per-route instruments ---
  requestTotalCounter = meter.createCounter('api_request', {
    description: 'Total number of requests per route',
  });
  durationHistogram = meter.createHistogram('api_request_duration_milliseconds', {
    description: 'Request duration in milliseconds',
    unit: 'ms',
    advice: {explicitBucketBoundaries: durationBuckets},
  });
  requestSizeHistogram = meter.createHistogram('api_request_size_bytes', {
    description: 'Request size in bytes',
    unit: 'By',
    advice: {explicitBucketBoundaries: requestSizeBuckets},
  });
  responseSizeHistogram = meter.createHistogram('api_response_size_bytes', {
    description: 'Response size in bytes',
    unit: 'By',
    advice: {explicitBucketBoundaries: responseSizeBuckets},
  });
```

**File:** rest/middleware/metricsHandler.js (L185-192)
```javascript
    res.on('finish', () => {
      inFlightCounter.add(-1);

      const duration = Date.now() - startTime;
      const path = toOpenApiPath(req, res);
      const code = String(res.statusCode);
      const method = req.method;
      const labels = {method, path, code};
```

**File:** rest/middleware/metricsHandler.js (L207-210)
```javascript
      requestTotalCounter.add(1, labels);
      durationHistogram.record(duration, labels);
      requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
      responseSizeHistogram.record(responseSize, labels);
```

**File:** rest/middleware/openapiHandler.js (L148-159)
```javascript
const openApiValidator = async (app) => {
  const validateResponses = isTestEnv() ? {allErrors: true} : false;
  const {default: OpenApiValidator} = await import('express-openapi-validator');
  app.use(
    OpenApiValidator.middleware({
      apiSpec: path.resolve(process.cwd(), getSpecPath(1)),
      ignoreUndocumented: true,
      validateRequests: false,
      validateResponses,
    })
  );
};
```

**File:** rest/server.js (L63-65)
```javascript
if (openApiValidatorEnabled || isTestEnv()) {
  await openApiValidator(app);
}
```

**File:** rest/server.js (L67-92)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
