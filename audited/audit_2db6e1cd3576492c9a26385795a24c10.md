### Title
Log Injection via Unsanitized `req.originalUrl` in `handleError()`

### Summary
`rest/middleware/httpErrorHandler.js` interpolates `req.originalUrl` directly into log strings passed to `logger.warn` and `logger.error` without any sanitization. The custom logger in `rest/logger.js` writes the composed string verbatim to `process.stdout` with no newline stripping or escape-sequence filtering. Because the application is explicitly configured with `trust proxy: true` and is designed to run behind a reverse proxy, an attacker can route a request through a proxy that normalizes/decodes percent-encoded characters, causing literal newline or ANSI escape bytes to reach `req.originalUrl` and be written into the log stream.

### Finding Description

**Exact code path:**

`rest/middleware/httpErrorHandler.js`, `handleError()`, lines 33–39: [1](#0-0) 

```js
logger.warn(
  `${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode} ${err.constructor.name} ${errorMessage}`
);
// ...
logger.error(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode}`, detailedMessage);
```

`req.originalUrl` is concatenated into the message string with no sanitization before being handed to the logger.

**Logger sink — `rest/logger.js`, `#log()`, line 69:** [2](#0-1) 

```js
const text = `${time} ${levelName} ${requestId} ${msg}${stack}\n`;
this.#write(text);
```

`#write` calls `process.stdout.write(line)` directly. There is no stripping of `\n`, `\r`, or ANSI escape sequences at any point.

**Root cause:** The application assumes `req.originalUrl` is a safe, printable string. It is not. Express sets `req.originalUrl` to the raw URL string as received from the HTTP layer; it is never percent-decoded by Express itself. However, the application is deployed behind a reverse proxy (`app.set('trust proxy', true)` in `rest/server.js` line 58): [3](#0-2) 

Many common reverse proxy configurations (nginx `proxy_pass` with `$request_uri` decoded, AWS ALB, Traefik with path normalization enabled) forward a decoded URL to the upstream Node.js process. When the proxy decodes `%0a` → `\n` before forwarding, the literal newline byte arrives in `req.originalUrl` and is written verbatim into the log.

**Why existing checks fail:** There are no checks. The middleware chain (`requestHandler.js`, `requestNormalizer.js`, `requestQueryParser`) validates query-parameter *values* for business logic (account IDs, timestamps, etc.) but never sanitizes the raw URL string for log-safe characters. No middleware strips or encodes control characters from `req.originalUrl` before it reaches `handleError`. [4](#0-3) 

### Impact Explanation

An attacker can forge arbitrary log lines, including lines that appear to be legitimate server-generated entries with any timestamp, log level, request ID, IP address, and message body. This undermines:

- **Log integrity / audit trails** — forged entries can hide real events or implicate innocent IPs.
- **SIEM / alerting** — injected `ERROR` or `WARN` lines can trigger false alerts or suppress real ones by flooding alert thresholds.
- **ANSI terminal injection** — injected `\x1b[...` sequences can corrupt terminal output for operators tailing logs, potentially hiding subsequent real log lines.

Severity: **Medium** (log injection alone does not achieve RCE or data exfiltration, but it directly undermines the integrity of the audit log for a financial-infrastructure service).

### Likelihood Explanation

- **No authentication required** — any unauthenticated HTTP request that triggers an error (e.g., a 400 `InvalidArgumentError` or 404 `NotFoundError`) reaches `handleError`.
- **Proxy decoding is common** — nginx's default `proxy_pass` with `$uri` (decoded) rather than `$request_uri` (raw) is a widespread misconfiguration; AWS ALB decodes paths by default.
- **Repeatable and scriptable** — a single crafted `curl` request through a decoding proxy is sufficient.
- **`trust proxy: true` confirms proxy presence** — the application is explicitly designed to run behind a proxy, making the precondition realistic.

### Recommendation

Sanitize `req.originalUrl` (and `req.ip`, `req.method`) before interpolating into log strings. Replace control characters and ANSI escape sequences:

```js
const sanitizeForLog = (s) =>
  String(s).replace(/[\x00-\x1f\x7f\x1b]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2,'0')}`);

logger.warn(
  `${sanitizeForLog(req.ip)} ${sanitizeForLog(req.method)} ${sanitizeForLog(req.originalUrl)} in ${elapsed} ms: ...`
);
```

Alternatively, apply the sanitization inside the `Logger#log` method so all callers benefit automatically. The same fix should be applied to the identical pattern in `rest/middleware/responseHandler.js` line 57. [5](#0-4) 

### Proof of Concept

**Precondition:** nginx (or any decoding proxy) sits in front of the Node.js service and forwards a decoded URL upstream (e.g., `proxy_pass http://upstream$uri;`).

**Steps:**

```bash
# Craft a URL where %0a decodes to \n at the proxy layer.
# The injected suffix mimics a legitimate log line.
INJECTED="%0a2024-01-01T00:00:00.000Z WARN abc12345 1.2.3.4 GET /api/v1/legit in 1 ms: 200"

curl -v "https://mirror-node-host/api/v1/accounts?account.id=${INJECTED}"
```

**Result in the log stream (after proxy decoding):**

```
2024-01-01T00:00:00.000Z WARN xyz99999 203.0.113.1 GET /api/v1/accounts?account.id=
2024-01-01T00:00:00.000Z WARN abc12345 1.2.3.4 GET /api/v1/legit in 1 ms: 200
```

The second line is entirely attacker-controlled and indistinguishable from a genuine log entry.

### Citations

**File:** rest/middleware/httpErrorHandler.js (L33-39)
```javascript
    logger.warn(
      `${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode} ${err.constructor.name} ${errorMessage}`
    );
  } else {
    errorMessage = statusCode.message;
    const detailedMessage = shouldPrintStacktrace(err) ? err : err.message;
    logger.error(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode}`, detailedMessage);
```

**File:** rest/logger.js (L60-71)
```javascript
  #log(level, msg, err) {
    if (level < this.#level) {
      return;
    }

    const time = new Date().toISOString();
    const levelName = Level.toString(level);
    const requestId = httpContext.get(constants.requestIdLabel) || 'Startup';
    const stack = err?.stack ? `\n${err.stack}` : '';
    const text = `${time} ${levelName} ${requestId} ${msg}${stack}\n`;
    this.#write(text);
  }
```

**File:** rest/server.js (L58-58)
```javascript
app.set('trust proxy', true);
```

**File:** rest/middleware/requestHandler.js (L38-69)
```javascript
const requestQueryParser = (queryString) => {
  const merge = (current, next) => {
    if (!Array.isArray(current)) {
      current = [current];
    }

    if (Array.isArray(next)) {
      current.push(...next);
    } else {
      current.push(next);
    }

    return current;
  };

  // parse first to benefit from qs query handling
  const parsedQueryString = qs.parse(queryString, queryOptions);

  const caseInsensitiveQueryString = {};
  for (const [key, value] of Object.entries(parsedQueryString)) {
    const lowerKey = key.toLowerCase();
    const canonicalValue = canonicalizeValue(lowerKey, value);
    if (lowerKey in caseInsensitiveQueryString) {
      // handle repeated values, merge into an array
      caseInsensitiveQueryString[lowerKey] = merge(caseInsensitiveQueryString[lowerKey], canonicalValue);
    } else {
      caseInsensitiveQueryString[lowerKey] = canonicalValue;
    }
  }

  return caseInsensitiveQueryString;
};
```

**File:** rest/middleware/responseHandler.js (L57-57)
```javascript
    logger.info(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${code}`);
```
