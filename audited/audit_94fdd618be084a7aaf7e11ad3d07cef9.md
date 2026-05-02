### Title
Unbounded User-Controlled Input in `handleError` Log Entries Enables Log-Flooding DoS via `parseHbarParam`

### Summary
The `handleError` middleware in `rest/middleware/httpErrorHandler.js` logs `err.message` verbatim via `logger.warn()` for all 4xx client errors, with no length truncation. The `parseHbarParam` utility in `rest/utils.js` constructs an `InvalidArgumentError` whose message directly embeds the raw, unsanitized `hbar` query parameter value supplied by the caller. Because three public, unauthenticated contract-results endpoints invoke `parseHbarParam`, any external user can craft requests that force arbitrarily large strings into the log pipeline, and the custom logger has no per-entry size cap, writing oversized entries synchronously and blocking the Node.js event loop.

### Finding Description

**Exact code path:**

1. **Entry points** — three unauthenticated routes call `utils.parseHbarParam(req.query.hbar)`:
   - `getContractResults` at `rest/controllers/contractController.js:1058`
   - `getContractResultsByTimestamp` at `rest/controllers/contractController.js:1008`
   - `getContractResultsByTransactionIdOrHash` at `rest/controllers/contractController.js:1128`

2. **Error construction** — `rest/utils.js:231`:
   ```js
   throw new InvalidArgumentError(`Invalid hbar parameter value: ${hbarParam}. Must be 'true' or 'false'`);
   ```
   `hbarParam` is `req.query.hbar` with zero length validation. The full value is embedded in `err.message`.

3. **Error handler logging** — `rest/middleware/httpErrorHandler.js:31-35`:
   ```js
   if (shouldReturnMessage(statusCode)) {          // true for 400 BAD_REQUEST
     errorMessage = err.message;
     logger.warn(
       `${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode} ${err.constructor.name} ${errorMessage}`
     );
   }
   ```
   Both `req.originalUrl` (user-controlled URL) and `errorMessage` (= `err.message`, containing the raw `hbar` value) are concatenated into a single string and passed to `logger.warn` with no truncation.

4. **Logger write path** — `rest/logger.js:73-88`:
   ```js
   #write(line) {
     const bytes = Buffer.byteLength(line);
     if (this.#position + bytes > this.#bufferSize) { this.#flush(); }
     // Line is larger than entire buffer so write directly
     if (bytes > this.#bufferSize) {
       process.stdout.write(line);   // synchronous, blocks event loop
       return;
     }
     ...
   }
   ```
   The buffer is only 4096 bytes (`rest/logger.js:31`). Any log line exceeding 4096 bytes bypasses the buffer and is written synchronously via `process.stdout.write`, blocking the single-threaded Node.js event loop for the duration of the I/O call.

**Root cause / failed assumption:** The code assumes error messages are short, bounded strings. No layer — not `parseHbarParam`, not `handleError`, not the logger — enforces a maximum length on user-supplied content before it reaches the I/O path.

**Why existing checks are insufficient:**
- `shouldReturnMessage` is a routing decision, not a sanitization gate.
- `InvalidArgumentError.forRequestValidation` (used by `validateReq`) only embeds parameter *keys*, not values — but `parseHbarParam` is called *after* `buildAndValidateFilters` and embeds the raw *value*.
- The logger's buffer overflow path (`bytes > this.#bufferSize`) is intended as a fast path for large lines, not a safety limit; it writes the full line unconditionally.
- No Express body/URL size limit is configured in `rest/server.js` for query strings; Node.js's default `--max-http-header-size` (8 KB) is the only natural bound, meaning a single request can produce a log entry of ~16 KB (URL + error message).

### Impact Explanation
Each malicious request produces a log entry of up to ~16 KB written synchronously to stdout, blocking the event loop. Under sustained high-rate flooding (thousands of requests per second, trivially achievable with `ab` or `wrk`), the cumulative effect is: (a) continuous event-loop stalls preventing other requests from being processed, (b) disk I/O saturation if stdout is redirected to a file or log aggregator, and (c) potential memory pressure in the log aggregation pipeline. The REST API becomes unresponsive, preventing clients from querying transaction state and operators from monitoring network health.

### Likelihood Explanation
The three affected endpoints (`/api/v1/contracts/results`, `/api/v1/contracts/results/:id`, `/api/v1/contracts/:id/results/:timestamp`) require no authentication. Any internet-accessible deployment is reachable by an anonymous attacker. The exploit requires only a standard HTTP client and a single line of shell script. It is trivially repeatable and automatable, making sustained flooding realistic.

### Recommendation
1. **Truncate user input before embedding in error messages.** In `parseHbarParam`, cap `hbarParam` before interpolation:
   ```js
   const display = String(hbarParam).slice(0, 64);
   throw new InvalidArgumentError(`Invalid hbar parameter value: ${display}. Must be 'true' or 'false'`);
   ```
2. **Truncate log fields in `handleError`.** Cap `req.originalUrl` and `errorMessage` before passing to the logger (e.g., 512 characters each).
3. **Add a per-entry size cap in the logger.** In `Logger#write`, truncate or drop lines exceeding a configurable maximum (e.g., 8 KB) rather than writing them synchronously without bound.
4. **Configure a URL/query-string size limit** in Express (e.g., via a custom middleware that rejects requests whose URL exceeds a threshold before routing).

### Proof of Concept
```bash
# Generate a ~7 KB payload
PAYLOAD=$(python3 -c "print('A' * 7000)")

# Single request — produces a ~14 KB log entry, triggers synchronous stdout.write
curl -s "http://<mirror-node-host>/api/v1/contracts/results?hbar=${PAYLOAD}" -o /dev/null

# Sustained flood — event loop stalls accumulate, API becomes unresponsive
ab -n 100000 -c 200 "http://<mirror-node-host>/api/v1/contracts/results?hbar=${PAYLOAD}"
```
Expected result: `logger.warn` is called with a string exceeding 4096 bytes on every request; `process.stdout.write` is invoked synchronously per request; under load the server stops responding to legitimate requests. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/middleware/httpErrorHandler.js (L31-35)
```javascript
  if (shouldReturnMessage(statusCode)) {
    errorMessage = err.message;
    logger.warn(
      `${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode} ${err.constructor.name} ${errorMessage}`
    );
```

**File:** rest/utils.js (L216-231)
```javascript
const parseHbarParam = (hbarParam) => {
  if (hbarParam === undefined || hbarParam === null) {
    return true; // Default to true for backward compatibility
  }

  if (typeof hbarParam === 'string') {
    const lower = hbarParam.toLowerCase();
    if (lower === 'true') {
      return true;
    }
    if (lower === 'false') {
      return false;
    }
  }

  throw new InvalidArgumentError(`Invalid hbar parameter value: ${hbarParam}. Must be 'true' or 'false'`);
```

**File:** rest/controllers/contractController.js (L1056-1058)
```javascript

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);
```

**File:** rest/logger.js (L73-84)
```javascript
  #write(line) {
    const bytes = Buffer.byteLength(line);

    if (this.#position + bytes > this.#bufferSize) {
      this.#flush();
    }

    // Line is larger than entire buffer so write directly
    if (bytes > this.#bufferSize) {
      process.stdout.write(line);
      return;
    }
```
