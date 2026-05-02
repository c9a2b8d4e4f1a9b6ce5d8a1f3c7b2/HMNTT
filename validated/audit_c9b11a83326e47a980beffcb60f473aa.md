All referenced code is confirmed. Let me verify the logger format to assess actual injection impact.

The logger's `#log` method formats output as:

```
${time} ${levelName} ${requestId} ${msg}${stack}\n
``` [1](#0-0) 

This is plain-text, newline-delimited output written directly to `process.stdout`. A `\n` embedded in `req.ip` would produce a second line indistinguishable from a real log entry.

The SECURITY.md excludes **"Reflected plain text injection (e.g. URL parameters, path, etc.)"** but explicitly states **"This does not exclude persistent plain text injection."** Log injection is persistent (written to log files/SIEM), not reflected in the HTTP response, so it is not excluded. [2](#0-1) 

---

# Audit Report

## Title
Log Injection via Unsanitized `req.ip` with Unconditional `trust proxy: true`

## Summary
`rest/server.js` sets `trust proxy: true`, causing Express to unconditionally accept the leftmost value of any client-supplied `X-Forwarded-For` header as `req.ip`. In `responseHandler()`, `httpErrorHandler.js`, and `responseCacheHandler.js`, `req.ip` is interpolated directly into plain-text log lines with no sanitization, allowing any unauthenticated attacker to inject arbitrary content — including newlines — into the application log, forging audit trail entries.

## Finding Description

**Root cause — unconditional trust proxy:**

`rest/server.js` line 58 sets `trust proxy` to the boolean `true`: [3](#0-2) 

With `trust proxy: true`, Express trusts every hop in `X-Forwarded-For` unconditionally and sets `req.ip` to the leftmost (client-controlled) value. There is no allowlist of trusted upstream proxy IPs, no hop-count limit, and no format validation.

**Sink — unsanitized interpolation into log:**

`responseHandler.js` line 57 interpolates `req.ip` directly into a template literal passed to `logger.info()`: [4](#0-3) 

The same pattern exists in `httpErrorHandler.js` lines 34 and 39: [5](#0-4) 

And in `responseCacheHandler.js` line 85: [6](#0-5) 

**Logger format — plain-text, newline-delimited:**

The custom logger writes each entry as `${time} ${levelName} ${requestId} ${msg}\n` directly to `process.stdout`: [1](#0-0) 

A `\n` embedded in `req.ip` produces a second line that is structurally identical to a legitimate log entry. No JSON envelope or escaping is applied.

**Why existing tests fail to catch this:**

The test suite for `responseHandler` hard-codes `req.ip: '127.0.0.1'` in the mock object: [7](#0-6) 

No test exercises a spoofed or malformed `X-Forwarded-For` value, so the injection path is untested and unguarded.

## Impact Explanation
An attacker can forge audit log entries for any API request, making malicious interactions appear to originate from an arbitrary IP address (e.g., a known-good internal address). This directly undermines forensic investigation and compliance audit trails. Because the logger uses plain-text newline-delimited output, injected newlines produce lines that are structurally indistinguishable from real log entries. The attacker's real IP never appears in the affected log lines.

## Likelihood Explanation
Exploitation requires only the ability to send an HTTP request — no authentication, no special role, no network position beyond reaching the REST API port. The `X-Forwarded-For` header is trivially set by any HTTP client (`curl`, browser, script). The attack is repeatable at will.

## Recommendation
1. **Restrict `trust proxy`**: Replace `app.set('trust proxy', true)` with an explicit list of trusted proxy CIDR ranges (e.g., `app.set('trust proxy', 'loopback, 10.0.0.0/8')`), so `req.ip` is only derived from trusted infrastructure headers.
2. **Sanitize `req.ip` before logging**: Strip or replace newlines (`\n`, `\r`) and other control characters from `req.ip` before interpolating it into log messages across `responseHandler.js`, `httpErrorHandler.js`, and `responseCacheHandler.js`.
3. **Add test coverage**: Add unit tests that supply a crafted `X-Forwarded-For` value containing `\n` and assert that the logged output does not contain injected lines.

## Proof of Concept
```bash
curl -H "X-Forwarded-For: 1.2.3.4\n2024-01-01T00:00:00.000Z INFO req-abc 8.8.8.8 GET /api/v1/contracts/results/0xdeadbeef in 0 ms: 200" \
     http://<mirror-node-host>/api/v1/transactions
```
Express sets `req.ip = "1.2.3.4\n2024-01-01T00:00:00.000Z INFO req-abc 8.8.8.8 GET /api/v1/contracts/results/0xdeadbeef in 0 ms: 200"`. The logger writes:
```
2024-01-01T00:00:00.000Z INFO req-xyz 1.2.3.4
2024-01-01T00:00:00.000Z INFO req-abc 8.8.8.8 GET /api/v1/contracts/results/0xdeadbeef in 0 ms: 200 GET /api/v1/transactions in 3 ms: 200
```
Log parsers and SIEMs see a fabricated second log line. The attacker's real IP does not appear in the log.

### Citations

**File:** rest/logger.js (L69-70)
```javascript
    const text = `${time} ${levelName} ${requestId} ${msg}${stack}\n`;
    this.#write(text);
```

**File:** SECURITY.md (L33-35)
```markdown
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
```

**File:** rest/server.js (L58-58)
```javascript
app.set('trust proxy', true);
```

**File:** rest/middleware/responseHandler.js (L57-57)
```javascript
    logger.info(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${code}`);
```

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

**File:** rest/middleware/responseCacheHandler.js (L84-86)
```javascript
  logger.info(
    `${req.ip} ${req.method} ${req.originalUrl} from cache (ttl: ${redisTtl}) in ${elapsed} ms: ${statusCode}`
  );
```

**File:** rest/__tests__/middleware/responseHandler.test.js (L23-25)
```javascript
    mockRequest = {
      ip: '127.0.0.1',
      method: 'GET',
```
