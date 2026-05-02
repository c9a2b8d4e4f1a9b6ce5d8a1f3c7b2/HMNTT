### Title
Unauthenticated Connection Pool Exhaustion via `getTopicMessages()` `zeroRandomPageCostQueryHint` Path

### Summary
The `getTopicMessages()` handler in `rest/topicmessage.js` unconditionally acquires a dedicated PostgreSQL client from the pool for every request where `limit != 1`, holding it through a full `BEGIN`/query/`COMMIT` transaction. Because the REST API has no rate limiting or concurrency control on the `/topics/:topicId/messages` endpoint, an unauthenticated attacker sending a moderate number of concurrent requests can exhaust the finite connection pool, causing all subsequent REST API requests (not just topic messages) to queue or fail until the pool drains.

### Finding Description

**Code path:**

In `rest/topicmessage.js` lines 142–143, the query hint is set for any `limit != 1`:

```js
const queryHint = limit !== 1 ? constants.zeroRandomPageCostQueryHint : undefined;
const messages = await getMessages(query, params, queryHint);
```

`getMessages` calls `pool.queryQuietly(query, params, preQueryHint)` with the hint truthy.

In `rest/utils.js` lines 1519–1527, `queryQuietly` branches on `preQueryHint`:

```js
if (!preQueryHint) {
  result = await this.query(query, params);   // uses pool internally, no dedicated client
} else {
  client = await this.connect();              // acquires dedicated client from pool
  client.on('error', clientErrorCallback);
  await client.query(`begin; ${preQueryHint}`);
  result = await client.query(query, params);
  await client.query('commit');
}
```

The dedicated client is held from `this.connect()` through the entire query execution and is only released in the `finally` block. The pool is configured with a hard `max: config.db.pool.maxConnections` ceiling in `rest/dbpool.js` line 14.

**Root cause:** The `zeroRandomPageCostQueryHint` path was designed as a query planner optimization but structurally requires a dedicated connection per in-flight request. There is no concurrency gate, semaphore, or rate limiter protecting this path on the REST API. The `authHandler` middleware only sets a per-user response `limit` cap — it does not throttle request rate or concurrent connections. No `express-rate-limit` or equivalent middleware is registered for the topics route in `rest/server.js`.

**Why `order=desc` matters:** With `order=desc` and `limit=<maxAllowed>`, the query scans the largest possible result set in reverse order, maximizing per-query execution time and thus maximizing the window during which each dedicated connection is held.

### Impact Explanation

When the pool is exhausted, `this.connect()` blocks until `connectionTimeoutMillis` elapses, at which point it throws. This causes HTTP 500 errors for all callers of any endpoint that uses `queryQuietly` with a hint — and also queues all other pool users. Because the pool is shared across all REST API handlers, a pool exhaustion event on the topics endpoint degrades or denies service to the entire mirror node REST API, affecting 100% of concurrent requests until the pool recovers.

### Likelihood Explanation

The endpoint is publicly accessible with no authentication required. The attacker needs only a standard HTTP client and knowledge of any valid `topicId`. Sending ~`maxConnections` concurrent requests (e.g., 10–50 depending on deployment) with `limit=<maxAllowed>&order=desc` is trivially achievable from a single machine. The attack is repeatable: as soon as connections are released, a new wave can be sent. No brute force, no credentials, no special protocol knowledge required.

### Recommendation

1. **Add a concurrency semaphore** in `queryQuietly` or at the handler level to cap the number of simultaneous dedicated-client acquisitions.
2. **Add rate limiting middleware** (e.g., `express-rate-limit`) to the REST API, specifically for endpoints that trigger the `preQueryHint` path.
3. **Consider using `SET LOCAL` via a savepoint** or advisory lock rather than a full dedicated client checkout, or use `pool.query('SET LOCAL ...')` within a managed transaction that does not hold a client across async awaits.
4. **Set a low `connectionTimeoutMillis`** and return HTTP 503 early rather than queuing indefinitely.

### Proof of Concept

```bash
# Discover a valid topicId from the public API, then:
for i in $(seq 1 50); do
  curl -s "https://<mirror-node>/api/v1/topics/0.0.1234/messages?limit=100&order=desc" &
done
wait
# Subsequent requests to ANY REST API endpoint will queue or return 500
curl "https://<mirror-node>/api/v1/transactions?limit=1"
```

**Preconditions:** Any valid `topicId`, no credentials needed.
**Trigger:** N concurrent requests where N ≥ `pool.maxConnections`, each holding a dedicated connection for the full query duration.
**Result:** Pool exhausted; all REST API endpoints return errors or time out until in-flight queries complete. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/topicmessage.js (L142-143)
```javascript
  const queryHint = limit !== 1 ? constants.zeroRandomPageCostQueryHint : undefined;
  const messages = await getMessages(query, params, queryHint);
```

**File:** rest/utils.js (L1519-1527)
```javascript
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

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** rest/constants.js (L131-131)
```javascript
const zeroRandomPageCostQueryHint = 'set local random_page_cost = 0';
```

**File:** rest/server.js (L82-92)
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
```
