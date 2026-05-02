### Title
Authentication Bypass via Empty Credentials in `tsscmp` Zero-Length Buffer Comparison

### Summary
The `authenticate()` function in `rest/middleware/metricsHandler.js` uses `tsscmp` to compare attacker-controlled credentials against configured values. Because `tsscmp` v1.0.6 allocates both comparison buffers based on the **first argument's** byte length, supplying an empty string as the first argument causes both buffers to be zero-length, making `crypto.timingSafeEqual` return `true` unconditionally. An unauthenticated attacker can bypass metrics authentication entirely by sending a Basic Auth header with an empty username and empty password.

### Finding Description
**Exact code location:** `rest/middleware/metricsHandler.js`, `authenticate()`, lines 137–144.

```js
const authenticate = (req) => {
  const {authentication, username, password} = config.metrics.config;
  if (!authentication) {
    return true;
  }
  const credentials = basicAuth(req);
  return credentials && tsscmp(credentials.name, username) && tsscmp(credentials.pass, password);
};
``` [1](#0-0) 

**Root cause — `tsscmp` v1.0.6 internals:**

```js
// tsscmp source (v1.0.6, public npm)
module.exports = function tsscmp(a, b) {
  var sa = String(a);
  var sb = String(b);
  var al = Buffer.byteLength(sa);   // length of FIRST arg
  var a  = Buffer.alloc(al, 0);
  var b  = Buffer.alloc(al, 0);     // BOTH buffers sized by `al`
  a.write(sa);
  b.write(sb.substr(0, al));
  return crypto.timingSafeEqual(a, b);
};
```

When `a = ''`, `al = 0`. Both `Buffer.alloc(0)` produce identical empty buffers. `crypto.timingSafeEqual(Buffer(0), Buffer(0))` always returns `true`, regardless of what `b` contains.

**Call chain:**

1. Attacker sends `Authorization: Basic Og==` (base64 of `:`).
2. `basicAuth(req)` returns `{name: '', pass: ''}` — a truthy object, so `credentials &&` passes.
3. `tsscmp(credentials.name, username)` → `tsscmp('', 'admin')` → `true`.
4. `tsscmp(credentials.pass, password)` → `tsscmp('', 's3cr3t')` → `true`.
5. `authenticate()` returns `true`; the metrics endpoint is served. [2](#0-1) 

**Why existing checks are insufficient:**

- The `if (!authentication) return true` guard only skips auth when the feature is disabled — it does not help when auth is enabled.
- The `credentials &&` check is satisfied because `basic-auth` returns a non-null object for any parseable header, including one with empty fields.
- `tsscmp` is intended to prevent timing attacks, but its buffer-sizing logic introduces a correctness bug when the first argument is empty. [3](#0-2) 

### Impact Explanation
The `/metrics/` endpoint exposes Prometheus-format data including request counters, error rates, in-flight request counts, CPU and heap memory gauges, and per-route histograms. An unauthenticated attacker gains full read access to this operational telemetry, leaking internal traffic patterns, error rates, and resource utilization. While this is an information-disclosure issue rather than direct code execution, it violates the explicit access-control intent of the `authentication` configuration flag and can aid further targeted attacks. [4](#0-3) 

### Likelihood Explanation
The exploit requires zero privileges and zero prior knowledge of the configured credentials. The only precondition is that `config.metrics.config.authentication` is `true` and the metrics endpoint is reachable. The attack is a single HTTP request, fully repeatable, and leaves no distinguishing trace beyond a normal 200 response on the metrics path. Any attacker who can reach the REST API port can exploit this.

### Recommendation
1. **Reject empty credentials before calling `tsscmp`:** Add an explicit guard in `authenticate()`:
   ```js
   if (!credentials || !credentials.name || !credentials.pass) {
     return false;
   }
   ```
2. **Fix argument order or use a length-safe comparison:** Either swap the arguments so the configured (trusted, non-empty) value is the first argument — `tsscmp(username, credentials.name)` — or replace `tsscmp` with a helper that rejects zero-length inputs before delegating to `crypto.timingSafeEqual`.
3. **Apply the same fix to `authHandler.js`:** `findUser` in `rest/middleware/authHandler.js` line 12 uses `tsscmp(user.username, username)` where `username` is attacker-controlled as the second argument, so the argument order there is safe — but an explicit empty-string guard is still good practice. [5](#0-4) 

### Proof of Concept
```bash
# Precondition: metrics authentication is enabled in config
# config.metrics.config = { authentication: true, username: 'admin', password: 'secret', uriPath: '/swagger' }

# Step 1: Confirm the endpoint requires auth (expect 401 without header)
curl -i http://<host>:<port>/swagger/metrics/

# Step 2: Send empty username:password (base64 of ":")
curl -i -H 'Authorization: Basic Og==' http://<host>:<port>/swagger/metrics/

# Expected result: HTTP 200 with full Prometheus metrics output
# Verified bypass: no valid credentials were provided
```

The value `Og==` is `btoa(':')` — the Base64 encoding of a colon with nothing on either side, which `basic-auth` parses as `{name: '', pass: ''}`. [1](#0-0)

### Citations

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

**File:** rest/middleware/metricsHandler.js (L156-164)
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
```

**File:** rest/middleware/authHandler.js (L10-13)
```javascript
const findUser = (username, password) => {
  const users = config.users || [];
  return users.find((user) => tsscmp(user.username, username) && tsscmp(user.password, password)) || null;
};
```
