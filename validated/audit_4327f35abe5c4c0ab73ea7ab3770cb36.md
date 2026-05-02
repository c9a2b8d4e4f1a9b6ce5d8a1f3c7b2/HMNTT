I have verified all the technical claims against the actual code. Here is my assessment:

**All cited code references are accurate:**

1. `blockRoute.js` line 13 — no middleware between route registration and handler. [1](#0-0) 

2. `blockController.js` `getByHashOrNumber` — validates format then immediately calls the service with no further guard. [2](#0-1) 

3. `recordFileService.js` `getByHashOrNumber` — confirmed `LIKE` prefix pattern (`hash + '%'`) against `record_file`, using the full `blocksQuery` (which includes `coalesce(size, length(bytes))`) with no `LIMIT` clause added at this layer. [3](#0-2) 

4. `blocksQuery` confirmed to include `coalesce(${RecordFile.SIZE}, length(${RecordFile.BYTES})) as size`. [4](#0-3) 

5. `server.js` middleware stack: `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler` — no rate limiting anywhere. [5](#0-4) 

6. `authHandler` only sets a `userLimitLabel` (response result count) for authenticated users — not a request-rate throttle. [6](#0-5) 

7. `grep_search` for `rateLimit|throttle|express-rate` across `rest/**/*.js` returned **no matches**.

---

Audit Report

## Title
Unauthenticated DoS via Unbounded LIKE Prefix Scan Flood on `GET /blocks/:hashOrNumber`

## Summary
The `GET /api/v1/blocks/:hashOrNumber` endpoint accepts unauthenticated requests and applies no application-level rate limiting. Any caller supplying a syntactically valid but non-matching hash causes the service to execute a `LIKE` prefix scan against the `record_file` table on every request. A sustained flood exhausts the database connection pool, producing a denial-of-service condition for all API consumers.

## Finding Description

**Route registration** — `blockRoute.js` line 13 registers the handler with no rate-limiting middleware:
```js
router.getExt('/:hashOrNumber', BlockController.getByHashOrNumber);
``` [7](#0-6) 

**Controller** — `getByHashOrNumber` validates format (64- or 96-char hex, optional `0x` prefix) then immediately issues a DB call with no further guard:
```js
const {hash, number} = validateHashOrNumber(req.params.hashOrNumber);
const block = await RecordFileService.getByHashOrNumber(hash, number);
``` [2](#0-1) 

**Service** — when a hash is supplied, `getByHashOrNumber` constructs a `LIKE` prefix query using the full `blocksQuery` (which includes `coalesce(size, length(bytes)) as size`) with no `LIMIT` clause at this layer:
```js
whereStatement += `${RecordFile.HASH} like $1`;
params.push(hash + '%');
const query = `${RecordFileService.blocksQuery} where ${whereStatement}`;
``` [8](#0-7) 

**Middleware inventory** — `server.js` registers `requestLogger`, `authHandler`, optional `metricsHandler`, and optional `responseCacheCheckHandler`. None implement per-IP or global request-rate limiting: [5](#0-4) 

**`authHandler`** only sets a custom *response-result limit* (`userLimitLabel`) for authenticated users; it does not throttle request frequency: [6](#0-5) 

**Root cause**: The application assumes infrastructure-level rate limiting (API gateway / reverse proxy). No application-level defense exists. An attacker who bypasses or is not subject to such infrastructure controls can drive unlimited DB queries.

## Impact Explanation
Each request with a valid-format, non-matching hash causes PostgreSQL to execute a prefix `LIKE` scan on `record_file.hash`. Even with a B-tree index, a high-volume flood saturates the bounded `pg` connection pool, increases I/O wait, and degrades or blocks all other API consumers. The `coalesce(size, length(bytes))` projection adds per-row CPU cost. The result is a full or partial service outage for all mirror node REST API users.

**Severity: High** — complete availability impact, no authentication required.

## Likelihood Explanation
- **Precondition**: None. No account, token, or credential is needed.
- **Attacker capability**: Any script generating random 64-char hex strings and sending HTTP GET requests. Trivially automated with `curl`, `ab`, `wrk`, or a simple Python loop.
- **Repeatability**: Continuous; the attacker simply keeps sending requests.
- **Detection evasion**: Requests are syntactically valid (pass OpenAPI schema validation), making WAF signature-based blocking difficult.

**Likelihood: High.**

## Recommendation
1. **Application-level rate limiting**: Add `express-rate-limit` (or equivalent) as global middleware in `server.js`, applied before route handlers, with a per-IP request cap.
2. **Query-level defense**: Add `LIMIT 1` explicitly to the `getByHashOrNumber` query in `recordFileService.js` (currently relies on `getSingleRow` behavior without an explicit clause).
3. **Connection pool timeout**: Configure `pg` pool with a short `connectionTimeoutMillis` and `idleTimeoutMillis` to fail fast under saturation rather than queuing indefinitely.
4. **Infrastructure enforcement**: Document and enforce that an API gateway with rate limiting is a hard deployment requirement, not an optional assumption.

## Proof of Concept
```bash
# Generate 64-char hex strings and flood the endpoint
python3 -c "
import os, requests, threading
def flood():
    while True:
        h = os.urandom(32).hex()  # valid 64-char hex
        requests.get(f'http://TARGET/api/v1/blocks/{h}')
threads = [threading.Thread(target=flood) for _ in range(100)]
[t.start() for t in threads]
[t.join() for t in threads]
"
```
Each request passes `validateHashOrNumber` (valid 64-char hex), reaches `RecordFileService.getByHashOrNumber`, and executes `SELECT ... FROM record_file WHERE hash LIKE '<random>%'`. At sufficient concurrency the `pg` pool is exhausted and all subsequent API requests (blocks, transactions, tokens, etc.) begin timing out or returning 500 errors.

### Citations

**File:** rest/routes/blockRoute.js (L9-13)
```javascript
const router = extendExpress(express.Router());

const resource = 'blocks';
router.getExt('/', BlockController.getBlocks);
router.getExt('/:hashOrNumber', BlockController.getByHashOrNumber);
```

**File:** rest/controllers/blockController.js (L114-118)
```javascript
  getByHashOrNumber = async (req, res) => {
    utils.validateReq(req);
    const {hash, number} = validateHashOrNumber(req.params.hashOrNumber);
    const block = await RecordFileService.getByHashOrNumber(hash, number);

```

**File:** rest/service/recordFileService.js (L64-70)
```javascript
  static blocksQuery = `select
    ${RecordFile.COUNT}, ${RecordFile.HASH}, ${RecordFile.NAME}, ${RecordFile.PREV_HASH},
    ${RecordFile.HAPI_VERSION_MAJOR}, ${RecordFile.HAPI_VERSION_MINOR}, ${RecordFile.HAPI_VERSION_PATCH},
    ${RecordFile.INDEX}, ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.GAS_USED},
    ${RecordFile.LOGS_BLOOM}, coalesce(${RecordFile.SIZE}, length(${RecordFile.BYTES})) as size
    from ${RecordFile.tableName}
  `;
```

**File:** rest/service/recordFileService.js (L164-178)
```javascript
  async getByHashOrNumber(hash, number) {
    let whereStatement = '';
    const params = [];
    if (hash) {
      hash = hash.toLowerCase();
      whereStatement += `${RecordFile.HASH} like $1`;
      params.push(hash + '%');
    } else {
      whereStatement += `${RecordFile.INDEX} = $1`;
      params.push(number);
    }

    const query = `${RecordFileService.blocksQuery} where ${whereStatement}`;
    const row = await super.getSingleRow(query, params);
    return row ? new RecordFile(row) : null;
```

**File:** rest/server.js (L83-98)
```javascript
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** rest/middleware/authHandler.js (L32-35)
```javascript
  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
```
