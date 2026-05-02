### Title
Unbounded `req.ip` from Attacker-Controlled `X-Forwarded-For` Causes Log Amplification DoS in `handleError()`

### Summary
The Express REST API unconditionally trusts all proxy headers (`trust proxy: true`), causing `req.ip` to be derived directly from the attacker-supplied `X-Forwarded-For` header with no length validation. In `handleError()`, `req.ip` is interpolated raw into log strings on every error path. An unauthenticated attacker can flood the server with requests carrying a maximally-sized `X-Forwarded-For` value, causing each error log entry to be orders of magnitude larger than expected and exhausting disk space or logger memory.

### Finding Description
**Root cause — unconditional proxy trust:**
`rest/server.js` line 58 sets `app.set('trust proxy', true)`, which instructs Express (via the `proxy-addr` package) to accept the leftmost value of any `X-Forwarded-For` header as the canonical client IP (`req.ip`). There is no IP allowlist, no hop count, and no length guard. The leftmost value is 100% attacker-controlled.

**Sink — unsanitized interpolation in `handleError()`:**
`rest/middleware/httpErrorHandler.js` lines 33–39 interpolate `req.ip` directly into two log calls:
```js
logger.warn(
  `${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ...`
);
logger.error(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ...`, ...);
```
No truncation, no validation, no sanitization of `req.ip` (or `req.originalUrl`) occurs anywhere in the middleware chain before these calls.

**Exploit flow:**
1. Attacker sends `GET /api/v1/transactions?limit=invalid` with header `X-Forwarded-For: AAAA...AAAA` (up to ~8 KB, Node.js's default `--max-http-header-size`).
2. The `InvalidArgumentError` path fires, `shouldReturnMessage()` returns `true`, and `logger.warn(...)` is called.
3. The log string is `<8KB garbage> GET /api/v1/transactions?limit=invalid in N ms: 400 InvalidArgumentError ...`.
4. No existing check limits `req.ip` length. No `--max-http-header-size` override exists in the codebase.
5. Repeated at high rate → log files grow at ~8–16 MB/s per attacker thread.

**Why existing checks are insufficient:**
- Node.js's 8 KB HTTP header limit is a parser-level guard, not an application-level one; the application never inspects or truncates `req.ip`.
- The nginx reverse proxy in `docker-compose.yml` uses `proxy_add_x_forwarded_for`, which *appends* the client IP to whatever the client already sent — it does not strip or limit the header value.
- Direct access to the Node.js service on port 5551 bypasses nginx entirely.
- `responseHandler.js` line 57 has the same `req.ip` interpolation pattern, compounding the surface.

### Impact Explanation
Every error response (400, 404, 500, 503) triggers a log write whose size is proportional to the attacker's `X-Forwarded-For` value. At 1,000 req/s with 8 KB headers, the log subsystem receives ~8 MB/s of attacker-controlled data. Sustained for minutes, this exhausts disk on typical deployments, can OOM the logger's in-memory buffer, and degrades or crashes the REST API process — a non-network DoS requiring zero authentication.

### Likelihood Explanation
Any unauthenticated external user can send HTTP requests. Crafting a large `X-Forwarded-For` header requires no special tooling (`curl -H "X-Forwarded-For: $(python3 -c "print('A'*8000)")" ...`). The error trigger is trivial (any invalid query parameter). The attack is fully repeatable and scriptable, and requires no knowledge of the application beyond the public API.

### Recommendation
1. **Restrict proxy trust to known proxies** — replace `app.set('trust proxy', true)` with a specific IP or CIDR (e.g., `app.set('trust proxy', '10.0.0.0/8')`) so `req.ip` is only derived from trusted upstream headers.
2. **Truncate `req.ip` before logging** — add a helper such as `const safeIp = (req.ip ?? '').slice(0, 45)` (max IPv6 length) and use it in all log interpolations in `httpErrorHandler.js` and `responseHandler.js`.
3. **Set `--max-http-header-size`** to a lower value (e.g., 4096) at the Node.js process level to reduce the per-request attack budget.

### Proof of Concept
```bash
# Generate a ~8000-byte X-Forwarded-For value and trigger a 400 error
LARGE_IP=$(python3 -c "print('1.2.3.4,' + 'A'*7990)")

# Repeat in a loop to exhaust disk
for i in $(seq 1 10000); do
  curl -s -o /dev/null \
    -H "X-Forwarded-For: $LARGE_IP" \
    "http://<mirror-node-rest>:5551/api/v1/transactions?limit=INVALID" &
done
wait

# Observe log file growth:
# Each entry will be ~8 KB instead of the normal ~100 bytes
# 10,000 requests → ~80 MB of log data from a single attacker
```
Expected result: `access.log` / stdout grows at an anomalous rate; at sustained load the disk fills or the logger's write queue backs up, causing process degradation.