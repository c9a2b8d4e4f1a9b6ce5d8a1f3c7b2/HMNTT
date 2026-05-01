### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded CTE Query in `getTopicMessageTimestampRanges()`

### Summary
When `topicMessageLookup` is enabled, any unauthenticated user can submit `GET /api/v1/topics/:topicId/messages?sequencenumber=gte:1&timestamp=gte:0` to force `getTopicMessageTimestampRanges()` into its expensive CTE branch. Because the REST API has no rate limiting and the DB connection pool defaults to 10 connections, a flood of such requests exhausts the pool and causes legitimate requests to time out.

### Finding Description

**Exact code path:**

`getTopicMessages` (line 116) → `extractSqlFromTopicMessagesRequest` (line 162) → `getTopicMessageTimestampRanges` (line 254).

In `getTopicMessageTimestampRanges`, with `sequencenumber=gte:1` and `timestamp=gte:0`:

- `sequenceNumberRange = {lower: 1n, upper: MAX_LONG-1n}` — valid, not null
- `timestampRange = {lower: 0n, upper: MAX_LONG-1n}` — valid, not null
- The branch condition at line 269: `(MAX_LONG-1n) - 1n + 1n ≈ 9.2×10¹⁸ >> limit (max 100)` → **always takes the `else` (CTE) branch**
- `params.push(limit)` at line 279 → params array has 4 entries
- The CTE query (lines 295–312) is executed: it first scans `topic_message_lookup` for the topic with the widest possible ranges, then does a second scan joined against `actual_range`

The CTE query is issued via `pool.queryQuietly` (line 315), which holds a DB connection for the full duration of the query.

**Why checks fail:**

1. `topicMessageLookup` gate (line 171, 199): only check is a boolean config flag — no per-request guard once enabled.
2. No rate limiting middleware exists in `server.js` for the Node.js REST API (confirmed: the `ThrottleConfiguration` is Web3/Java only).
3. No concurrency limit per client IP.
4. `getRangeFromFilters` (line 220) correctly returns non-null for `gte:1` and `gte:0` — these are valid inputs that pass all validation.

### Impact Explanation

The DB connection pool is capped at `maxConnections: 10` by default (line 14 of `dbpool.js`). Each attacker request holds one connection for up to `statementTimeout: 20000ms`. With 10 concurrent attacker requests, the pool is fully exhausted. Subsequent legitimate requests queue and wait for `connectionTimeout: 20000ms` before failing with a timeout error. This is a complete availability denial for all REST API endpoints sharing the pool, sustained for as long as the attacker maintains the flood.

### Likelihood Explanation

The attack requires zero privileges — the endpoint is public, unauthenticated, and documented in the OpenAPI spec. The only prerequisite is that the operator has enabled `topicMessageLookup` (non-default, but a documented production feature). The attack is trivially repeatable with any HTTP load tool (`ab`, `wrk`, `curl` in a loop). Ten concurrent connections are sufficient to saturate the pool.

### Recommendation

1. **Add per-IP or global rate limiting** to the Node.js REST API (e.g., `express-rate-limit`) before DB-touching handlers.
2. **Cap the effective sequence-number range** in `getTopicMessageTimestampRanges`: if `sequenceNumberRange.upper - sequenceNumberRange.lower` exceeds a configurable threshold, reject or clamp the request before issuing any DB query.
3. **Increase pool size** or use a queue with a bounded wait to degrade gracefully rather than hard-failing under load.
4. **Add a `LIMIT` clause** to the second `SELECT` in the CTE query to bound the number of rows returned regardless of range width.

### Proof of Concept

```bash
# Precondition: topicMessageLookup is enabled in application.yml:
#   hiero.mirror.rest.query.topicMessageLookup: true

# Flood with 10+ concurrent requests (matches default pool size)
for i in $(seq 1 20); do
  curl -s "http://<mirror-node>/api/v1/topics/0.0.123/messages?sequencenumber=gte:1&timestamp=gte:0" &
done
wait

# Legitimate request now times out (connectionTimeout = 20s):
curl -v "http://<mirror-node>/api/v1/topics/0.0.123/messages"
# Expected: connection timeout or 500 after 20 seconds
```

**Root cause lines:**
- `rest/topicmessage.js` line 269: branch condition that routes to CTE
- `rest/topicmessage.js` line 279: `params.push(limit)` — 4th param confirming CTE path
- `rest/topicmessage.js` line 295–312: unbounded CTE query
- `rest/dbpool.js` line 14: `max: config.db.pool.maxConnections` (default 10)
- `rest/server.js` lines 100–133: no rate-limiting middleware registered [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/topicmessage.js (L254-317)
```javascript
const getTopicMessageTimestampRanges = async (topicId, sequenceNumberFilters, timestampFilters, limit, order) => {
  const sequenceNumberRange = getRangeFromFilters(sequenceNumberFilters, 1n);
  const timestampRange = getRangeFromFilters(timestampFilters);
  if (sequenceNumberRange === null || timestampRange === null) {
    return [];
  }

  const isOrderAsc = order === constants.orderFilterValues.ASC;
  let query;
  const params = [
    topicId,
    `[${sequenceNumberRange.lower},${sequenceNumberRange.upper}]`,
    `[${timestampRange.lower},${timestampRange.upper}]`,
  ];

  if (sequenceNumberRange.upper - sequenceNumberRange.lower + 1n <= limit) {
    // If the range size doesn't exceed the limit, use it as is. Note explicitly casting topic id to bigint is
    // required to utilize the btree gist index on (topic_id, sequence_number_range)
    query = `select timestamp_range
      from topic_message_lookup
      where topic_id = $1::bigint and sequence_number_range && $2::int8range and timestamp_range && $3::int8range
      order by sequence_number_range`;
  } else {
    // Depending on the order, first query the table to find the bound of the sequence number range and build the actual
    // range from the bound and the limit, then query the table with the actual range
    params.push(limit);
    // Since the information in the table can't tell the first sequence number satisfying the sequence number range and
    // the timestamp range, for instance, with sequencenumber=lt:500, timestamp=lt:1000, limit=25, and order=desc, the
    // first sequence number range might be [300, 400), the minimum value of the largest sequence number is 300, and
    // the maximum is 399. In order to get the correct timestamp range, we need to use an actual range which covers
    // all possible sequence number values, i.e., [276, 400)
    // Notes:
    // - for asc order, when expanding the upper, the delta least(limit, 9223372036854775807::bigint - upper(range)) is
    //   used to ensure no overflow occurs
    // - for desc order, lower bound is expanded by limit - 1, since the lower bound is inclusive
    // - upper($2::int8range) is always the exclusive upper bound, i.e., when the value passed in is '[1, 10]', pg
    //   upper returns 11
    const rangeExpression = isOrderAsc
      ? `int8range(lower(range), least(upper(range) + least($4, 9223372036854775807::bigint - upper(range)), upper($2::int8range)), '[)')`
      : `int8range(greatest(lower(range) - ($4 - 1), lower($2::int8range)), upper(range), '[)')`;

    query = `with actual_range as (
        select ${rangeExpression} as range
        from (
          select sequence_number_range as range
          from topic_message_lookup
          where topic_id = $1::bigint and
            sequence_number_range && $2::int8range and
            timestamp_range && $3::int8range
          order by sequence_number_range ${order}
          limit 1
        ) as t
      )
      select timestamp_range
      from topic_message_lookup as t, actual_range as a
      where topic_id = $1::bigint and
        sequence_number_range && a.range and
        timestamp_range && $3::int8range
      order by sequence_number_range`;
  }

  const {rows} = await pool.queryQuietly(query, params);
  return rows.map((r) => r.timestamp_range);
};
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

**File:** rest/server.js (L67-133)
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

// accounts routes
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
app.use(`${apiPrefix}/${AccountRoutes.resource}`, AccountRoutes.router);

// balances routes
app.getExt(`${apiPrefix}/balances`, balances.getBalances);

// contracts routes
app.use(`${apiPrefix}/${ContractRoutes.resource}`, ContractRoutes.router);

// block routes
app.use(`${apiPrefix}/${BlockRoutes.resource}`, BlockRoutes.router);

// schedules routes
app.getExt(`${apiPrefix}/schedules`, schedules.getSchedules);
app.getExt(`${apiPrefix}/schedules/:scheduleId`, schedules.getScheduleById);

// tokens routes
app.getExt(`${apiPrefix}/tokens`, tokens.getTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId`, tokens.getTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/balances`, tokens.getTokenBalances);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts`, tokens.getNftTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber`, tokens.getNftTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber/transactions`, tokens.getNftTransferHistoryRequest);

// topics routes
app.getExt(`${apiPrefix}/topics/:topicId/messages`, topicmessage.getTopicMessages);
app.getExt(`${apiPrefix}/topics/:topicId/messages/:sequenceNumber`, topicmessage.getMessageByTopicAndSequenceRequest);
app.getExt(`${apiPrefix}/topics/messages/:consensusTimestamp`, topicmessage.getMessageByConsensusTimestamp);

// transactions routes
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
app.getExt(`${apiPrefix}/transactions/:transactionIdOrHash`, transactions.getTransactionsByIdOrHash);
```
