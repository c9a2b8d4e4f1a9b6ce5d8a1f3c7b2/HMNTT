### Title
Unauthenticated Unbounded Pagination on `/api/v1/blocks` Exhausts DB Connection Pool, Causing REST API DoS and Potential Importer Starvation

### Summary
The `getBlocks()` handler in `rest/controllers/blockController.js` applies no per-IP rate limiting and allows any unauthenticated client to paginate through the entire `record_file` table via `generateNextLink()`. Each page request holds a PostgreSQL connection for the duration of the query. Many concurrent clients issuing rapid sequential pagination requests can saturate the shared connection pool, starving both the REST API and, if PostgreSQL's global `max_connections` ceiling is reached, the importer's write path — effectively partitioning the mirror node from the live network.

### Finding Description

**Code path:**

`rest/controllers/blockController.js` — `getBlocks()` (lines 101–112) calls `extractSqlFromBlockFilters()` then `RecordFileService.getBlocks()`, and finally `generateNextLink()`.

`generateNextLink()` (lines 90–99):
```js
generateNextLink = (req, blocks, filters) => {
  return blocks.length
    ? utils.getPaginationLink(
        req,
        blocks.length !== filters.limit,   // false = more pages exist
        {[filterKeys.BLOCK_NUMBER]: last(blocks).index},
        filters.order
      )
    : null;
};
```
A non-null next link is emitted whenever `blocks.length === filters.limit`, i.e., whenever a full page was returned. There is no upper bound on the number of pages an unauthenticated client may follow.

`extractLimitFromFilters()` (lines 57–61) caps the per-page limit at `maxLimit` (default 100 per docs), but contains a logic error: when `limit.value > maxLimit` it falls back to `defaultLimit` (25) instead of `maxLimit`. This does not prevent the attack; it only means the attacker uses `limit=100` to maximise rows per request.

`RecordFileService.getBlocks()` (`rest/service/recordFileService.js`, lines 149–162) issues a raw SQL query against `record_file` for every page:
```js
const query = RecordFileService.blocksQuery + `${where} order by ${filters.orderBy} ${filters.order} limit ${filters.limit}`;
const rows = await super.getRows(query, params);
```
`super.getRows()` calls `this.pool().queryQuietly(...)`, which acquires a connection from the shared `pg` pool configured in `rest/dbpool.js` (lines 7–16):
```js
const poolConfig = {
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  ...
};
```
The pool is finite. `RecordFileService.pool()` returns `primaryPool` (line 203–205), the same pool used by all REST API handlers.

**No rate-limiting middleware exists for the REST API blocks route.** The middleware stack (`rest/middleware/`) contains `authHandler.js`, `requestHandler.js`, `requestNormalizer.js`, `responseCacheHandler.js`, `responseHandler.js`, `openapiHandler.js`, `metricsHandler.js`, and `httpErrorHandler.js` — none of which implement per-IP or global request-rate throttling for the blocks endpoint. The `ThrottleConfiguration`/`ThrottleManagerImpl` throttle found in the codebase is scoped exclusively to the `web3` module (`/api/v1/contracts/call`), not the REST API.

**Root cause:** The REST API blocks endpoint is unauthenticated, has no rate limiting, and `generateNextLink()` will produce a valid next link for every full page returned, enabling indefinite traversal of the entire `record_file` table. Each in-flight request holds a DB connection for the duration of the SQL query. Concurrent clients can hold all `maxConnections` connections simultaneously.

### Impact Explanation

1. **REST API DoS:** Once `maxConnections` connections are held, new REST API requests queue until `connectionTimeoutMillis` expires, returning errors to all users.
2. **Importer starvation:** The importer is a separate JVM process with its own JDBC connection pool connecting to the same PostgreSQL instance. PostgreSQL enforces a global `max_connections` limit. If the REST API's pool is sized close to that limit (or if multiple REST API replicas are deployed), the importer cannot acquire a connection to write new `record_file` rows, halting block ingestion and partitioning the mirror node from the live network.
3. **`statement_timeout` is insufficient:** It limits individual query duration but does not prevent a high-concurrency attacker from keeping connections continuously occupied by issuing new requests as soon as old ones complete.

Severity: **High** — unauthenticated, no special tooling required, directly impacts data availability and network synchronisation.

### Likelihood Explanation

- **Preconditions:** None. No authentication, no API key, no special network position required.
- **Tooling:** A simple script using `curl` or any HTTP client following the `links.next` field suffices. The attacker needs only to know the public API endpoint.
- **Repeatability:** The attack is trivially repeatable and can be sustained indefinitely as long as new blocks are being added (the chain never ends, so `generateNextLink` never returns null for a full-page response starting from block 0).
- **Scale:** On a mainnet mirror node with tens of millions of blocks, a single client with `limit=100` requires ~hundreds of thousands of requests to traverse the chain; with 50–100 concurrent clients this is achievable in minutes.

### Recommendation

1. **Add per-IP rate limiting** to the REST API using middleware such as `express-rate-limit`, applied globally or specifically to the `/api/v1/blocks` route.
2. **Fix the limit fallback bug** in `extractLimitFromFilters` (line 60): `limit.value > maxLimit ? defaultLimit : limit.value` should be `limit.value > maxLimit ? maxLimit : limit.value`.
3. **Reserve DB connections for the importer** by configuring PostgreSQL `pg_hba.conf` or connection pooler (e.g., PgBouncer) to guarantee a minimum number of connections for the importer role, independent of REST API load.
4. **Add a `statement_timeout` at the PostgreSQL role level** for the REST API database user to enforce a hard ceiling on query duration regardless of pool configuration.
5. **Consider cursor-based pagination with server-side session state** or signed/expiring pagination tokens to prevent clients from issuing arbitrarily many independent page requests.

### Proof of Concept

```bash
# Step 1: Start initial request from block 0
NEXT="/api/v1/blocks?block.number=gte:0&limit=100&order=asc"
BASE="https://<mirror-node-host>"

# Step 2: Spawn N concurrent clients, each following the pagination chain
for i in $(seq 1 100); do
  (
    LINK="$NEXT"
    while [ -n "$LINK" ]; do
      RESP=$(curl -s "${BASE}${LINK}")
      LINK=$(echo "$RESP" | jq -r '.links.next // empty')
    done
  ) &
done
wait

# Result: 100 concurrent clients each hold a DB connection for the duration
# of each query. With maxConnections exhausted:
# - All other REST API requests time out with connectionTimeoutMillis errors
# - If PostgreSQL max_connections is reached, the importer cannot write new blocks
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/blockController.js (L57-61)
```javascript
  extractLimitFromFilters = (filters) => {
    const limit = findLast(filters, {key: filterKeys.LIMIT});
    const maxLimit = getEffectiveMaxLimit();
    return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
  };
```

**File:** rest/controllers/blockController.js (L90-99)
```javascript
  generateNextLink = (req, blocks, filters) => {
    return blocks.length
      ? utils.getPaginationLink(
          req,
          blocks.length !== filters.limit,
          {[filterKeys.BLOCK_NUMBER]: last(blocks).index},
          filters.order
        )
      : null;
  };
```

**File:** rest/controllers/blockController.js (L101-112)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);

    res.locals[responseDataLabel] = {
      blocks: blocks.map((model) => new BlockViewModel(model)),
      links: {
        next: this.generateNextLink(req, blocks, formattedFilters),
      },
    };
  };
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
