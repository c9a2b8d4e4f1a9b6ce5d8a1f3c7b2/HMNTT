### Title
Unauthenticated Unbounded `contract_log` Table Scan via `GET /contracts/results/logs` with No Filters

### Summary
`getContractLogs()` in `rest/controllers/contractController.js` accepts `GET /contracts/results/logs` with zero query parameters from any unauthenticated caller. With the default configuration (`bindTimestampRange=false`), the resulting `contract_log` database query carries no timestamp bounds whatsoever, producing a full table scan. Because the REST Node.js server has no rate-limiting middleware, an attacker can flood this endpoint to exhaust database connection pool capacity and degrade the service for all users.

### Finding Description

**Exact code path:**

`getContractLogs` (line 820) accepts the request with no filters and calls `extractContractLogsMultiUnionQuery(filters)` with `contractId=undefined`: [1](#0-0) 

Because `contractId === undefined` and no `transactionHash` is present, the branch at line 678 calls `optimizeTimestampFilters` with an empty filter array: [2](#0-1) 

`optimizeTimestampFilters` calls `parseTimestampFilters` with `filterRequired=false` and `allowOpenRange=true`, so an empty array returns `{range: null, eqValues: [], neValues: []}` without error: [3](#0-2) 

Since `eqValues.length === 0`, it calls `bindTimestampRange(null, order)`. With the **default** `bindTimestampRange=false`, this function returns `{range: null}` immediately — no DB query, no bounds: [4](#0-3) 

Back in `extractContractLogsMultiUnionQuery`, the guard at line 506 only skips when `timestampFilters.length !== 0 && optimizedTimestampFilters.length === 0`. With an empty input, `timestampFilters.length` is `0`, so the condition is `false` and execution continues with **no timestamp conditions** in the query: [5](#0-4) 

The resulting SQL query against `contract_log` has no `WHERE consensus_timestamp` clause — a full sequential scan of the entire table.

**No rate limiting exists in the REST API.** `rest/server.js` registers only `cors`, `compression`, `httpContext`, `authHandler`, and optional metrics/cache middleware — no `express-rate-limit` or equivalent: [6](#0-5) 

**`bindTimestampRange` defaults to `false`** per the documented configuration: [7](#0-6) 

Even when `bindTimestampRange=true`, the `getFirstTransactionTimestamp` DB query is cached after the first call (line 50: `if (timestamp === undefined)`), so that is not the bottleneck — but the `contract_log` scan still runs over a 60-day window per request, which remains expensive under flood conditions: [8](#0-7) 

### Impact Explanation

On a production mirror node with months of contract log history, a no-filter `GET /contracts/results/logs` forces a full sequential scan of the `contract_log` table. Each such request holds a database connection for the duration of the scan. Concurrent floods exhaust the connection pool, causing all other API endpoints that share the same pool to queue or time out. The impact is a complete denial of service for all REST API consumers with no economic cost to the attacker.

### Likelihood Explanation

The endpoint is publicly documented in the OpenAPI spec (`/api/v1/contracts/results/logs`) with no authentication requirement. No API key, token, or credential is needed. The attack requires only an HTTP client and a loop. The default configuration (`bindTimestampRange=false`) is the most dangerous state and is what operators get out of the box. The attack is trivially repeatable from a single machine or distributed across multiple IPs since there is no per-IP or global request rate limit in the REST service.

### Recommendation

1. **Require at least one timestamp filter** for `GET /contracts/results/logs` when no `contractId` is present. Reject requests with HTTP 400 if no timestamp bound is supplied (mirror the `filterRequired=true` path in `parseTimestampFilters`).
2. **Enable `bindTimestampRange=true` by default** so that even if a partial bound is supplied, the query window is always capped at `maxTransactionsTimestampRangeNs`.
3. **Add rate-limiting middleware** (e.g., `express-rate-limit`) to the REST server, specifically targeting expensive scan endpoints.
4. **Add a DB-level statement timeout** for the REST pool so runaway scans are killed before they exhaust connections.

### Proof of Concept

```bash
# Single request — returns results from a full contract_log table scan
curl -s "https://<mirror-node-host>/api/v1/contracts/results/logs"

# Flood — no authentication, no rate limit, each request triggers a full scan
for i in $(seq 1 500); do
  curl -s "https://<mirror-node-host>/api/v1/contracts/results/logs" &
done
wait
# Result: database connection pool exhausted; all other API endpoints begin
# returning 500 errors or timing out.
```

### Citations

**File:** rest/controllers/contractController.js (L384-392)
```javascript
const optimizeTimestampFilters = async (timestampFilters, order) => {
  const filters = [];

  const {range, eqValues, neValues} = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
  if (range?.isEmpty()) {
    return {filters};
  }

  const {range: optimizedRange, next} = eqValues.length === 0 ? await bindTimestampRange(range, order) : {range};
```

**File:** rest/controllers/contractController.js (L506-508)
```javascript
    if (timestampFilters.length !== 0 && optimizedTimestampFilters.length === 0) {
      return {skip: true};
    }
```

**File:** rest/controllers/contractController.js (L678-685)
```javascript
    } else if (contractId === undefined) {
      // Optimize timestamp filters only when there is no transaction hash and transaction id
      const {filters: timestampFilters, next} = await optimizeTimestampFilters(bounds.primary.getAllFilters(), order);
      bounds.primary = new Bound(filterKeys.TIMESTAMP);
      query.bounds.next = next;
      for (const filter of timestampFilters) {
        bounds.primary.parse(filter);
      }
```

**File:** rest/controllers/contractController.js (L820-835)
```javascript
  getContractLogs = async (req, res) => {
    // get sql filter query, params, limit and limit query from query filters
    const filters = alterTimestampRange(utils.buildAndValidateFilters(req.query, acceptedContractLogsParameters));
    checkTimestampsForTopics(filters);

    // Workaround: set the request path in handler so later in the router level generic middleware it won't be
    // set to /contracts/results/:transactionIdOrHash
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`;
    res.locals[responseDataLabel] = {
      logs: [],
      links: {
        next: null,
      },
    };

    const query = await this.extractContractLogsMultiUnionQuery(filters);
```

**File:** rest/timestampRange.js (L19-22)
```javascript
const bindTimestampRange = async (range, order) => {
  if (!queryConfig.bindTimestampRange) {
    return {range};
  }
```

**File:** rest/timestampRange.js (L46-64)
```javascript
const getFirstTransactionTimestamp = (() => {
  let timestamp;

  const func = async () => {
    if (timestamp === undefined) {
      const {rows} = await pool.queryQuietly(`select consensus_timestamp
                                              from transaction
                                              order by consensus_timestamp
                                              limit 1`);
      if (rows.length !== 1) {
        return 0n; // fallback to 0
      }

      timestamp = rows[0].consensus_timestamp;
      logger.info(`First transaction's consensus timestamp is ${timestamp}`);
    }

    return BigInt(timestamp);
  };
```

**File:** rest/server.js (L67-98)
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

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** docs/configuration.md (L579-579)
```markdown
| `hiero.mirror.rest.query.bindTimestampRange`                             | false                   | Whether to bind the timestamp range to maxTimestampRange                                                                                                                                      |
```
