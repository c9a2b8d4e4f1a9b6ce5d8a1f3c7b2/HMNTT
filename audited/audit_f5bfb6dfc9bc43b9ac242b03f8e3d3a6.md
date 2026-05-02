### Title
Unauthenticated DoS via Unbounded Complex CTE Queries Against `topic_message_lookup` When `topicMessageLookup` Is Enabled

### Summary
When `config.query.topicMessageLookup` is `true`, any unauthenticated user can craft a `/api/v1/topics/:topicId/messages` request with a wide `sequencenumber` range filter that forces the expensive CTE branch in `getTopicMessageTimestampRanges()`. The REST module has no application-level rate limiting, and flooding concurrent requests can exhaust the finite DB connection pool, rendering the mirror node REST API unavailable.

### Finding Description

**Exact code location:** `rest/topicmessage.js`, `getTopicMessageTimestampRanges()`, lines 254–317, specifically the branch at line 269.

**Root cause:** The branch condition at line 269 is:
```js
if (sequenceNumberRange.upper - sequenceNumberRange.lower + 1n <= limit)
``` [1](#0-0) 

When this condition is false (range width > limit), the complex CTE path executes: [2](#0-1) 

This CTE involves:
1. A subquery against `topic_message_lookup` with GiST range overlap operators (`&&`) ordered and limited to 1 row.
2. A range expansion computation.
3. A second join query against `topic_message_lookup` using the expanded range.

This entire path is gated on `config.query.topicMessageLookup`: [3](#0-2) 

**Exploit flow:**
1. Attacker sends: `GET /api/v1/topics/0.0.1/messages?sequencenumber=gt:1&sequencenumber=lt:9223372036854775806`
2. `getRangeFromFilters` computes `lower=2`, `upper=MAX_LONG-2`.
3. `upper - lower + 1n` is astronomically larger than `limit` (default 25), so the complex CTE branch is always taken.
4. Each request fires two DB queries (the CTE lookup + the final `topic_message` query).
5. With no rate limiting in the REST module, an attacker floods concurrent requests, exhausting the `max` pool connections (default `mirror_rest` cap: 250 server-side connections per Helm config). [4](#0-3) 

**Why existing checks fail:**
- The `statement_timeout` limits individual query duration but does not prevent connection pool exhaustion from many concurrent short-lived queries.
- The REST middleware stack (`authHandler`, `openApiValidator`, `responseCacheCheckHandler`, `responseHandler`) contains **no rate-limiting middleware**. [5](#0-4) 
- The throttle configuration found (`ThrottleConfiguration.java`, `ThrottleManagerImpl.java`) applies only to the **web3 Java module**, not the Node.js REST module.
- Input validation only checks that `sequencenumber` is a valid positive long — it does not bound the range width. [6](#0-5) 

**Precondition:** `config.query.topicMessageLookup` must be `true`. The test suite confirms the default is `false`: [7](#0-6) 
This means the vulnerability is only exploitable on deployments that have explicitly enabled this feature.

### Impact Explanation
When `topicMessageLookup` is enabled, an attacker with no credentials can saturate the REST module's DB connection pool, causing all subsequent REST API requests (not just topic message queries) to fail with connection timeout errors. This takes down the mirror node REST API entirely for the duration of the attack. The mirror node REST API is the primary read interface for wallets, explorers, and dApps querying Hedera state.

### Likelihood Explanation
The attack requires zero authentication and zero knowledge beyond a valid topic ID (which is publicly enumerable). The request is a single HTTP GET with two query parameters. Any attacker with a modest botnet or even a single machine with high concurrency (e.g., `ab -n 10000 -c 500`) can sustain the flood. The only barrier is the non-default `topicMessageLookup` flag, which reduces likelihood on default deployments but makes production deployments using this feature fully exposed.

### Recommendation
1. **Add rate limiting to the REST module** (e.g., `express-rate-limit` or an ingress-level rate limiter) scoped per IP or per endpoint.
2. **Bound the sequence number range width** in `getTopicMessageTimestampRanges()`: if `sequenceNumberRange.upper - sequenceNumberRange.lower + 1n` exceeds a configurable maximum (e.g., `10 * limit`), reject with HTTP 400.
3. **Add a `pg_cancel_backend`-compatible query timeout** at the application layer in addition to `statement_timeout` to shed load faster.
4. Consider requiring authentication for the `topicMessageLookup`-enabled code path.

### Proof of Concept
```bash
# Precondition: topicMessageLookup=true in config
# Step 1: Confirm the complex CTE branch is triggered
curl "https://<mirror-node>/api/v1/topics/0.0.1/messages?sequencenumber=gt:1&sequencenumber=lt:9223372036854775806"
# Returns 200 (or 404 if topic doesn't exist, but DB query still fires)

# Step 2: Flood with concurrent requests to exhaust connection pool
ab -n 50000 -c 300 \
  "https://<mirror-node>/api/v1/topics/0.0.1/messages?sequencenumber=gt:1&sequencenumber=lt:9223372036854775806"

# Step 3: Observe all REST API endpoints begin returning 503/timeout
curl "https://<mirror-node>/api/v1/accounts/0.0.2"
# Expected: connection timeout or pool exhaustion error
```

### Citations

**File:** rest/topicmessage.js (L199-209)
```javascript
  if (topicMessageLookupEnabled) {
    const ranges = await getTopicMessageTimestampRanges(topicId, sequenceNumberFilters, timestampFilters, limit, order);
    if (ranges.length === 0) {
      return {};
    }

    const timestampRangeCondition = ranges
      .map((r) => `(consensus_timestamp >= $${params.push(r.begin)} and consensus_timestamp < $${params.push(r.end)})`)
      .join(' or ');
    conditions.push(`(${timestampRangeCondition})`);
  }
```

**File:** rest/topicmessage.js (L254-268)
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

```

**File:** rest/topicmessage.js (L269-275)
```javascript
  if (sequenceNumberRange.upper - sequenceNumberRange.lower + 1n <= limit) {
    // If the range size doesn't exceed the limit, use it as is. Note explicitly casting topic id to bigint is
    // required to utilize the btree gist index on (topic_id, sequence_number_range)
    query = `select timestamp_range
      from topic_message_lookup
      where topic_id = $1::bigint and sequence_number_range && $2::int8range and timestamp_range && $3::int8range
      order by sequence_number_range`;
```

**File:** rest/topicmessage.js (L295-312)
```javascript
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

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```

**File:** rest/__tests__/config.test.js (L225-227)
```javascript
      strictTimestampParam: true,
      topicMessageLookup: false,
      transactions: {
```
