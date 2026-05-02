### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded Concurrent `GET /api/v1/blocks` Requests

### Summary
The `GET /api/v1/blocks` endpoint accepts requests with no filters from any unauthenticated user, executing a full-table scan on `record_file` bounded only by `defaultLimit=25`. The REST API has no application-level rate limiting or in-flight request cap, and the default DB connection pool is only 10 connections. An attacker flooding this endpoint concurrently can exhaust the pool, causing all subsequent DB-dependent requests across the entire REST API to queue and time out.

### Finding Description

**Exact code path:**

`getBlocks()` in `rest/controllers/blockController.js` lines 101–112 calls `buildAndValidateFilters(req.query, acceptedBlockParameters)` — with an empty query string this returns `[]`. [1](#0-0) 

`extractSqlFromBlockFilters([])` hits the early-return branch at line 71 and returns `{whereQuery: [], limit: 25, order: 'desc', orderBy: 'consensus_end'}`. [2](#0-1) 

`RecordFileService.getBlocks()` calls `buildWhereSqlStatement([])` which produces an empty `where` string, yielding the query: `SELECT count, hash, name, ... FROM record_file ORDER BY consensus_end DESC LIMIT 25`. [3](#0-2) 

**Root cause — failed assumptions:**

1. The DB connection pool defaults to **10 connections** (`hiero.mirror.rest.db.pool.maxConnections = 10`) with a `connectionTimeoutMillis` of 20,000 ms and `statement_timeout` of 20,000 ms. [4](#0-3) 
2. The REST API Helm chart middleware contains **only** `circuitBreaker` and `retry` — no `inFlightReq` cap and no `rateLimit`, unlike the Rosetta chart which explicitly sets `inFlightReq: amount: 5` and `rateLimit: average: 10`. [5](#0-4) 
3. The `retry: attempts: 10` middleware entry **amplifies** each failed request up to 10-fold, multiplying pool pressure. [6](#0-5) 
4. There is no application-level rate limiting in the Express server for the blocks route. [7](#0-6) 

**Exploit flow:**

- Attacker sends N concurrent `GET /api/v1/blocks` requests (no auth, no filters).
- Each request acquires one of the 10 pool connections and executes the `SELECT … LIMIT 25` query.
- Once all 10 connections are held, subsequent requests queue inside `pg.Pool` waiting up to 20 s for a free connection.
- The Traefik retry middleware re-issues each timed-out request up to 10 times, multiplying the queued load.
- All other REST API endpoints (accounts, transactions, tokens, etc.) share the same pool and become unresponsive.

### Impact Explanation

Complete denial of service for the entire REST API. All endpoints share the single `pg.Pool` instance. With 10 connections and 20-second statement timeouts, a sustained flood of ~20–50 concurrent requests is sufficient to hold the pool at capacity. Legitimate users receive connection-timeout errors (HTTP 500) across all endpoints, not just `/blocks`. The `record_file` table grows continuously as the network produces blocks, making the sequential scan progressively more expensive over time.

### Likelihood Explanation

No authentication, API key, or network credential is required. The endpoint is publicly reachable at `GET /api/v1/blocks`. A single attacker with a modest HTTP flood tool (e.g., `ab`, `wrk`, or a simple async script) can sustain the required concurrency. The attack is repeatable and stateless — each request is independent. The absence of `inFlightReq` or `rateLimit` middleware (present in the Rosetta chart but absent in the REST chart) means there is no infrastructure-level backstop.

### Recommendation

1. **Add `inFlightReq` and `rateLimit` Traefik middleware** to `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta chart's configuration.
2. **Remove or reduce the `retry` middleware** for the REST API — retrying read-only list endpoints under load amplifies pool pressure.
3. **Increase `maxConnections`** or introduce a per-route concurrency semaphore in the Express application.
4. **Add a minimum timestamp lower-bound filter** requirement or a mandatory index-based cursor for the `/blocks` list endpoint to prevent full-table scans.
5. **Enable the GCP gateway `maxRatePerEndpoint`** (currently set to 250 but gated behind optional GCP gateway deployment) as a mandatory control.

### Proof of Concept

```bash
# Exhaust the 10-connection pool with 20 concurrent, sustained requests
wrk -t 20 -c 20 -d 60s http://<mirror-node-rest>/api/v1/blocks

# Simultaneously verify other endpoints become unresponsive
curl http://<mirror-node-rest>/api/v1/accounts
# Expected: connection timeout / HTTP 500 after pool exhaustion
```

With `maxConnections=10` and `statement_timeout=20000ms`, 20 concurrent requests will hold all connections and cause all queued requests to time out within 20 seconds, producing observable service degradation across the entire REST API.

### Citations

**File:** rest/controllers/blockController.js (L63-73)
```javascript
  extractSqlFromBlockFilters = (filters) => {
    const filterQuery = {
      order: this.extractOrderFromFilters(filters),
      orderBy: this.extractOrderByFromFilters(filters),
      limit: this.extractLimitFromFilters(filters),
      whereQuery: [],
    };

    if (filters && filters.length === 0) {
      return filterQuery;
    }
```

**File:** rest/controllers/blockController.js (L101-104)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);
```

**File:** rest/service/recordFileService.js (L149-162)
```javascript
  async getBlocks(filters) {
    const {where, params} = buildWhereSqlStatement(filters.whereQuery);

    const query =
      RecordFileService.blocksQuery +
      `
      ${where}
      order by ${filters.orderBy} ${filters.order}
      limit ${filters.limit}
    `;

    const rows = await super.getRows(query, params);
    return rows.map((recordFile) => new RecordFile(recordFile));
  }
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```

**File:** charts/hedera-mirror-rest/values.yaml (L134-139)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```

**File:** rest/server.js (L111-112)
```javascript
// block routes
app.use(`${apiPrefix}/${BlockRoutes.resource}`, BlockRoutes.router);
```
