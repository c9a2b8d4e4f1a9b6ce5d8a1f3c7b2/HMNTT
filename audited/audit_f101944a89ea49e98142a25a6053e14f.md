### Title
Log Injection via Unsanitized `req.originalUrl` in `responseCacheCheckHandler`

### Summary
The `responseCacheCheckHandler` function in `rest/middleware/responseCacheHandler.js` logs `req.originalUrl` directly into a plain-text log message with no sanitization. The custom logger in `rest/logger.js` performs zero input neutralization before writing to stdout. An unprivileged attacker can craft a URL containing newline characters (delivered via a URL-decoding reverse proxy, which is standard in production) or ANSI escape sequences to inject forged log entries, enabling them to obscure cache poisoning activity from defenders.

### Finding Description
**Exact code path:**

`rest/middleware/responseCacheHandler.js`, lines 84–86:
```js
logger.info(
  `${req.ip} ${req.method} ${req.originalUrl} from cache (ttl: ${redisTtl}) in ${elapsed} ms: ${statusCode}`
);
```

`req.originalUrl` is user-controlled and flows directly into the log message string. The logger's `#log` method in `rest/logger.js` (lines 69–70) performs no sanitization:
```js
const text = `${time} ${levelName} ${requestId} ${msg}${stack}\n`;
this.#write(text);
```

**Root cause:** The failed assumption is that `req.originalUrl` contains only printable, single-line ASCII. In reality it is attacker-controlled and can contain newlines (via a URL-decoding reverse proxy such as nginx with `proxy_pass`) or ANSI escape codes.

**Exploit flow:**
1. Attacker sends: `GET /api/v1/transactions%0A2024-01-01T00:00:00.000Z%20INFO%20abc123%20203.0.113.1%20GET%20/api/v1/transactions%20from%20cache%20(ttl:%20300)%20in%205%20ms:%20200 HTTP/1.1`
2. nginx (or any URL-normalizing reverse proxy) decodes `%0A` → `\n` before forwarding to Node.js.
3. `req.originalUrl` in Express now contains a literal newline.
4. The logger writes: `2024-01-01T... INFO <reqId> 1.2.3.4 GET /api/v1/transactions\n2024-01-01T00:00:00.000Z INFO abc123 203.0.113.1 GET /api/v1/transactions from cache (ttl: 300) in 5 ms: 200\n`
5. Log aggregators (Splunk, ELK, CloudWatch) parse the injected line as a legitimate second log event.

**Why existing checks fail:** There are no checks. The `requestQueryParser` in `rest/middleware/requestHandler.js` only canonicalizes query parameter keys/values for routing purposes — it does not sanitize `req.originalUrl` for logging. The logger itself (`rest/logger.js`) has no allowlist, no newline stripping, and no encoding step. The same unsanitized pattern is repeated in `rest/middleware/responseHandler.js` (line 57) and `rest/middleware/httpErrorHandler.js` (lines 34, 39), confirming this is a systemic absence of log sanitization.

### Impact Explanation
An attacker can forge arbitrary log entries that appear structurally identical to legitimate cache-hit records (same timestamp format, level, requestId, IP, method, URL, status). This directly enables:
- **Audit trail poisoning**: Injected entries can make it appear that a specific IP address accessed specific transaction endpoints from cache, fabricating false access patterns.
- **Attack obfuscation**: During a cache poisoning campaign, the attacker can inject fake "normal" cache-hit entries to drown out anomalous entries in SIEM/log-aggregation tooling, delaying or preventing defender detection.
- **ANSI injection**: Even without newlines, injecting `\x1b[2K` (erase line) or color codes into terminal-based log viewers causes visual corruption, hiding real log lines from operators.

Severity: **Medium** (log integrity compromise, no direct data exfiltration, but directly enables covering tracks for higher-severity attacks).

### Likelihood Explanation
- **No privilege required**: any unauthenticated HTTP client can send the crafted request.
- **Reverse proxy decoding is the norm**: nginx `proxy_pass` with default settings, AWS ALB, and most API gateways decode percent-encoded characters before forwarding — this is the standard production topology for this service.
- **Trivially repeatable**: the attacker can fire thousands of injected log entries per second to overwhelm legitimate entries.
- **Widely known technique**: CWE-117 / OWASP "Log Injection" is a well-documented, low-skill attack.

### Recommendation
1. **Sanitize before logging**: strip or replace newlines and carriage returns from all user-controlled fields before interpolation:
   ```js
   const sanitize = (s) => String(s).replace(/[\r\n]/g, '_');
   logger.info(
     `${sanitize(req.ip)} ${sanitize(req.method)} ${sanitize(req.originalUrl)} from cache ...`
   );
   ```
2. **Switch to structured (JSON) logging**: emit log records as JSON objects. Newlines inside a JSON string value are escaped (`\n`), making injection structurally impossible for line-oriented log parsers.
3. **Apply the fix consistently** across all three affected files: `responseCacheHandler.js`, `responseHandler.js`, and `httpErrorHandler.js`.

### Proof of Concept
```bash
# Assumes nginx reverse proxy with proxy_pass (standard production setup)
# The %0A is decoded to \n by nginx before forwarding to Node.js

curl -v "http://mirror-node-api/api/v1/transactions%0A$(date -u +%Y-%m-%dT%H:%M:%S.000Z)%20INFO%20forged123%20198.51.100.1%20GET%20/api/v1/transactions%20from%20cache%20(ttl:%20300)%20in%203%20ms:%20200"
```

Expected log output (two lines parsed as separate events by log aggregators):
```
2026-05-01T12:00:00.123Z INFO real-req-id 1.2.3.4 GET /api/v1/transactions
2026-05-01T12:00:00.000Z INFO forged123 198.51.100.1 GET /api/v1/transactions from cache (ttl: 300) in 3 ms: 200
```

The second line is entirely attacker-controlled and indistinguishable from a legitimate cache-hit log entry.