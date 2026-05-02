### Title
Connection Pool Exhaustion via Unthrottled `zeroRandomPageCostQueryHint` Transaction in `getTopicMessages()`

### Summary
Every request to `/api/v1/topics/:topicId/messages` with a limit other than 1 (including the default limit) causes `queryQuietly` to check out a **dedicated PostgreSQL client** from the pool and hold it for the full duration of a `BEGIN; SET LOCAL random_page_cost = 0` → SELECT → COMMIT transaction. Because there is no rate limiting or per-IP concurrency cap on this endpoint, an unprivileged attacker can flood the endpoint with concurrent requests, exhausting the finite connection pool and causing all subsequent REST API queries to fail with connection timeout errors.

### Finding Description

**Code path:**

`rest/topicmessage.js`, `getTopicMessages()`, lines 142–143:
```js
const queryHint = limit !== 1 ? constants.zeroRandomPageCostQueryHint : undefined;
const messages = await getMessages(query, params, queryHint);
``` [1](#0-0) 

`defaultLimit` is never 1 (it is the configured response limit default, e.g. 25), so `queryHint` is always set for unauthenticated default requests. [2](#0-1) 

`getMessages` calls `pool.queryQuietly(query, params, preQueryHint)`: [3](#0-2) 

Inside `queryQuietly` in `rest/utils.js`, when `preQueryHint` is truthy:
```js
client = await this.connect();           // dedicated connection checked out
client.on('error', clientErrorCallback);
await client.query(`begin; ${preQueryHint}`);
result = await client.query(query, params);
await client.query('commit');
``` [4](#0-3) 

The client is only released in the `finally` block after all three round-trips complete (or after rollback on error): [5](#0-4) 

The pool is initialized with a finite `max: config.db.pool.maxConnections` and `connectionTimeoutMillis`: [6](#0-5) 

**Root cause:** The `preQueryHint` path unconditionally upgrades a simple pool query into a session-level transaction requiring a dedicated connection. There is no rate limiting, no per-IP concurrency cap, and no queue depth limit on the `/topics/:topicId/messages` endpoint. A search of the REST layer confirms zero rate-limiting middleware:

```
grep rateLimit|rate_limit|express-rate|helmet|slowDown rest/**/*.js → No matches found
```

**Why `statement_timeout` is insufficient:** `statement_timeout` limits how long the SELECT itself runs, but the connection is still held across `BEGIN` + SET + SELECT + COMMIT. An attacker does not need queries to run forever — they only need enough concurrent in-flight requests to keep the pool saturated. With a pool of 250 connections (pgbouncer `max_user_connections: 250` for `mirror_rest`) and a statement timeout of e.g. 20 s, the attacker must sustain ≥250 concurrent requests, which is trivially achievable from a single machine. [7](#0-6) 

### Impact Explanation
When the pool is exhausted, `this.connect()` blocks until `connectionTimeoutMillis` elapses, then throws. All REST API endpoints share the same pool, so exhaustion of connections by the topic messages endpoint causes 100% of REST API queries to fail with connection timeout errors for the duration of the attack. This degrades the mirror node's REST API service entirely, satisfying the ≥30% processing capacity threshold for the mirror node's public-facing query layer.

### Likelihood Explanation
The endpoint is unauthenticated and publicly accessible. No special knowledge, credentials, or network position is required. A single attacker machine can open hundreds of concurrent HTTP connections. The attack is repeatable, stateless, and requires no prior reconnaissance beyond knowing a valid `topicId` (which is public information). The attacker does not need to cause slow queries — even fast queries that complete within milliseconds still hold a dedicated connection for the full transaction round-trip, and at high concurrency this is sufficient to saturate the pool.

### Recommendation
1. **Add per-IP rate limiting** on the REST API layer (e.g., `express-rate-limit`) to cap concurrent or per-second requests per client.
2. **Avoid dedicated connection checkout for the hint**: Instead of using `BEGIN; SET LOCAL`, consider setting `random_page_cost` at the session level via a pool `afterConnect` hook, or use a PostgreSQL query hint extension (e.g., `pg_hint_plan`) that does not require a transaction, allowing the normal `pool.query()` path (no dedicated connection checkout) to be used.
3. **Limit pool connection hold time**: Add an explicit `lock_timeout` or reduce `connectionTimeoutMillis` so pool exhaustion fails fast and does not cascade.
4. **Add a concurrency semaphore** in the application layer to cap the number of simultaneous in-flight `queryQuietly` calls that use the `preQueryHint` path.

### Proof of Concept
```bash
# Requires: a running mirror node REST API and a known topicId (e.g., 0.0.1234)
# Send 300 concurrent requests (exceeds default pool size of 250)

seq 300 | xargs -P 300 -I{} curl -s \
  "http://<mirror-node-host>/api/v1/topics/0.0.1234/messages" \
  -o /dev/null &

# Simultaneously, observe legitimate requests failing:
curl -v "http://<mirror-node-host>/api/v1/transactions"
# Expected: connection timeout / 503 error due to pool exhaustion
```

Each of the 300 concurrent requests triggers `queryQuietly` with `preQueryHint = 'set local random_page_cost = 0'`, checking out a dedicated connection. Once the pool (`maxConnections`, default 250 for `mirror_rest`) is saturated, all subsequent REST API requests — including unrelated endpoints — fail until connections are released.

### Citations

**File:** rest/topicmessage.js (L12-12)
```javascript
const {default: defaultLimit} = getResponseLimit();
```

**File:** rest/topicmessage.js (L142-143)
```javascript
  const queryHint = limit !== 1 ? constants.zeroRandomPageCostQueryHint : undefined;
  const messages = await getMessages(query, params, queryHint);
```

**File:** rest/topicmessage.js (L331-334)
```javascript
const getMessages = async (query, params, preQueryHint) => {
  const {rows} = await pool.queryQuietly(query, params, preQueryHint);
  logger.debug(`getMessages returning ${rows.length} entries`);
  return rows.map((row) => new TopicMessage(row));
```

**File:** rest/utils.js (L1518-1527)
```javascript
    try {
      if (!preQueryHint) {
        result = await this.query(query, params);
      } else {
        client = await this.connect();
        client.on('error', clientErrorCallback);
        await client.query(`begin; ${preQueryHint}`);
        result = await client.query(query, params);
        await client.query('commit');
      }
```

**File:** rest/utils.js (L1540-1544)
```javascript
    } finally {
      if (client !== undefined) {
        client.off('error', clientErrorCallback);
        client.release();
      }
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```
