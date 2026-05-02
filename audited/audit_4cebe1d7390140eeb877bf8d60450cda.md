### Title
Unauthenticated Multi-Query DB Amplification DoS via `GET /contracts/results?block.number=<N>`

### Summary
The `getContractResults()` handler in `rest/controllers/contractController.js` executes up to 4 sequential/parallel database queries per unauthenticated HTTP request when the `block.number` filter is supplied. The REST API has no application-level rate limiting, allowing any external user to exhaust the database connection pool through concurrent requests and cause a non-network-based denial of service.

### Finding Description

**Exact code path:**

**Step 1 — Block index lookup (DB Query 1):**
In `extractContractResultsByIdQuery` (lines 486–501), when `blockFilter.key === filterKeys.BLOCK_NUMBER`, the handler unconditionally calls: [1](#0-0) 

This executes `SELECT consensus_start, consensus_end, hash, index FROM record_file WHERE index = $1 LIMIT 1` against the database.

**Step 2 — Timestamp range optimization (conditional DB Query 2):**
After the block lookup, `optimizeTimestampFilters` is called (line 504–505) because `contractId === undefined` in the `getContractResults` path: [2](#0-1) 

This calls `bindTimestampRange` from `rest/timestampRange.js`. When `block.number` is provided, both timestamp bounds are already set from the block data, so `getFirstTransactionTimestamp` (which issues a DB query) is skipped. However, the `optimizeTimestampFilters` call itself is still an async await point.

**Step 3 — Main contract results query (DB Query 2):** [3](#0-2) 

**Step 4 — Two parallel DB queries (DB Queries 3 & 4):**
If any rows are returned, two queries fire in parallel: [4](#0-3) 

This is `getEthereumTransactionsByPayerAndTimestampArray` and `getRecordFileBlockDetailsFromTimestampArray` — both hit the database simultaneously.

**Total: 4 DB queries per request.**

**No rate limiting exists in the REST API:**
The `server.js` middleware stack is: [5](#0-4) 

The registered middleware is: `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`. There is no rate-limiting middleware. The `authHandler` only sets a custom response-size `limit` for authenticated users — it does not throttle request rates for unauthenticated callers: [6](#0-5) 

The `ThrottleManagerImpl` (bucket4j-based) exists only in the `web3/` Java module for `POST /api/v1/contracts/call`: [7](#0-6) 

It is entirely separate from the Node.js REST API and provides zero protection for `GET /contracts/results`.

**Root cause:** The REST API assumes infrastructure-level rate limiting (e.g., reverse proxy) will protect it, but no such protection is enforced at the application layer. The `block.number` filter path is particularly expensive because it always issues the block-lookup query before the main query, and then unconditionally fires two parallel follow-up queries if any results exist.

### Impact Explanation
An attacker sending N concurrent requests to `GET /contracts/results?block.number=1` causes up to 4N simultaneous database queries. With a typical PostgreSQL connection pool of 10–100 connections, a few hundred concurrent HTTP requests saturate the pool, causing all subsequent queries (across all API endpoints) to queue or fail. This results in full service unavailability for all users of the mirror node REST API — a non-network-based DoS affecting the entire node's read API surface.

### Likelihood Explanation
The exploit requires zero privileges, zero authentication, and zero knowledge beyond the public API documentation (the `block.number` parameter is documented in `rest/api/v1/openapi.yml` line 648). The attacker needs only an HTTP client capable of sending concurrent requests (e.g., `ab`, `wrk`, `curl` in a loop). The attack is repeatable, stateless, and requires no prior state setup. Any block number that exists (or even one that doesn't — the block-lookup query still fires) triggers the amplification.

### Recommendation
1. **Add application-level rate limiting** to the Node.js REST API using a middleware such as `express-rate-limit` or `rate-limiter-flexible`, applied globally or specifically to expensive endpoints like `/contracts/results`.
2. **Short-circuit early on block miss**: The block-lookup query already returns `{skip: true}` when no block is found (line 500), but the query itself still executes. Consider caching recent block index → timestamp range mappings to avoid a DB round-trip per request.
3. **Add a DB connection pool guard**: Configure `pg` pool `max` and `connectionTimeoutMillis` to fail fast under saturation rather than queuing indefinitely.
4. **Enforce a concurrency limit** at the application layer (e.g., using a semaphore on the pool) so that a single client IP cannot hold all pool connections.

### Proof of Concept
```bash
# Send 200 concurrent requests, each triggering 4 DB queries = 800 simultaneous DB queries
seq 200 | xargs -P200 -I{} curl -s \
  "http://<mirror-node-host>/api/v1/contracts/results?block.number=1" \
  -o /dev/null

# Observe: subsequent legitimate API calls begin timing out or returning 500
curl "http://<mirror-node-host>/api/v1/contracts/results"
# Expected: timeout or DB connection pool exhaustion error
```

Reproducible steps:
1. Deploy the mirror node REST API with default configuration (no external rate limiter).
2. Identify any valid block number (e.g., `block.number=1`).
3. Fire 200+ concurrent `GET /api/v1/contracts/results?block.number=1` requests.
4. Each request triggers: `getRecordFileBlockDetailsFromIndex` → `getContractResultsByIdAndFilters` → parallel `getEthereumTransactionsByPayerAndTimestampArray` + `getRecordFileBlockDetailsFromTimestampArray`.
5. The PostgreSQL connection pool is exhausted; all API endpoints become unresponsive.

### Citations

**File:** rest/controllers/contractController.js (L488-492)
```javascript
      if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
      } else {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
      }
```

**File:** rest/controllers/contractController.js (L504-505)
```javascript
    const {filters: optimizedTimestampFilters, next} =
      contractId === undefined ? await optimizeTimestampFilters(timestampFilters, order) : {filters: timestampFilters};
```

**File:** rest/controllers/contractController.js (L1072-1075)
```javascript
    const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
    if (rows.length === 0) {
      return;
    }
```

**File:** rest/controllers/contractController.js (L1083-1086)
```javascript
    const [ethereumTransactionMap, recordFileMap] = await Promise.all([
      ContractService.getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps),
      RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps),
    ]);
```

**File:** rest/server.js (L82-98)
```javascript
app.use(httpContext.middleware);
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

**File:** rest/middleware/requestHandler.js (L22-29)
```javascript
const requestLogger = async (req, res) => {
  const requestId = await randomString(8);
  httpContext.set(requestIdLabel, requestId);

  // set default http OK code for reference
  res.locals.statusCode = httpStatusCodes.OK.code;
  res.locals[requestStartTime] = Date.now();
};
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-43)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

```
