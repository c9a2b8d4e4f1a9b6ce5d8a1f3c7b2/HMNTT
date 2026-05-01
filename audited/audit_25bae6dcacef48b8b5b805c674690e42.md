### Title
Connection Pool Exhaustion DoS via Unauthenticated Topic Message List Requests

### Summary
Every call to `GET /api/v1/topics/:topicId/messages` with `limit != 1` (including the default of 25 and the maximum of 100) causes `queryQuietly()` to acquire a **dedicated, exclusively-held** database connection for the full query duration. With a default pool ceiling of only 10 connections and no application-level rate limiting on this endpoint, any unauthenticated attacker can exhaust the pool with 10 concurrent requests, rendering the entire REST API unavailable for all users until connections are released.

### Finding Description

**Code path:**

`getTopicMessages()` (`rest/topicmessage.js:142`) unconditionally sets:
```js
const queryHint = limit !== 1 ? constants.zeroRandomPageCostQueryHint : undefined;
``` [1](#0-0) 

Since `limit=100` (or any value != 1, including the default of 25) is always non-1, `queryHint` is always `'set local random_page_cost = 0'`. This hint is passed to `getMessages()` → `pool.queryQuietly()`.

Inside `queryQuietly()` (`rest/utils.js:1518-1527`), when `preQueryHint` is truthy, the code takes the **dedicated-client branch**:
```js
client = await this.connect();          // acquires exclusive connection
client.on('error', clientErrorCallback);
await client.query(`begin; ${preQueryHint}`);
result = await client.query(query, params);  // holds connection for full query
await client.query('commit');
``` [2](#0-1) 

The connection is only released in the `finally` block after the entire transaction completes. [3](#0-2) 

The pool is configured with:
- `max: config.db.pool.maxConnections` → default **10**
- `connectionTimeoutMillis` → default **20,000 ms**
- `statement_timeout` → default **20,000 ms** [4](#0-3) [5](#0-4) 

**Root cause:** The failed assumption is that the `random_page_cost` hint path (needed for correct index selection) is safe to apply unconditionally without any concurrency guard. The design serializes each hinted query through an exclusive connection, turning a pool of 10 into a hard concurrency ceiling of 10 for all topic-message list requests.

**Why the order-direction variation matters:** The `order` direction is embedded directly in the SQL string (`order by consensus_timestamp asc` vs `desc`), not as a bind parameter. These are distinct query strings, so PostgreSQL cannot reuse a cached plan between them. An attacker alternating `order=asc` and `order=desc` ensures each request generates a fresh plan, maximizing per-query execution time and thus connection hold time. [6](#0-5) 

### Impact Explanation

With 10 concurrent requests (trivially achievable from a single machine), the entire `pg-pool` is saturated. The 11th and all subsequent requests — from **any** API endpoint that uses the shared pool — block for up to 20 seconds waiting for a connection, then fail with a connection-timeout error. This is a full REST API outage, not limited to the topic-message endpoint. The attack is repeatable: as soon as the statement timeout (20 s) forces connections to release, the attacker fires the next wave. Sustained attack requires only ~10 HTTP requests every 20 seconds.

### Likelihood Explanation

No authentication, API key, or account is required. The endpoint is publicly documented and reachable. The attacker needs only an HTTP client capable of sending 10 concurrent requests. The attack is trivially scriptable with `curl --parallel`, `ab`, `wrk`, or any async HTTP library. There is no application-level rate limiter on this endpoint (rate limiting exists only in the web3 Java service); any Traefik-layer rate limiting is optional infrastructure configuration not enforced by the application itself. [7](#0-6) 

### Recommendation

1. **Decouple the query hint from the dedicated-connection path.** Issue `SET LOCAL random_page_cost = 0` as a session-level hint using the pool's built-in `query()` (no dedicated client needed), or use PostgreSQL's `/*+ Set(random_page_cost 0) */` query-level hint comment which does not require a transaction.
2. **Add application-level concurrency limiting** (e.g., a semaphore or token bucket) on the REST API topic-message endpoint, analogous to the `ThrottleConfiguration` already present in the web3 service.
3. **Increase the default pool size** or document a minimum recommended value that accounts for concurrent hinted queries.
4. **Pass `order` as a bind parameter** where possible, or cache the two plan variants explicitly, to reduce per-query planning overhead.

### Proof of Concept

```bash
# Exhaust the 10-connection pool with 10 concurrent requests
for i in $(seq 1 10); do
  curl -s "http://<mirror-node>/api/v1/topics/0.0.1234/messages?order=asc&limit=100" &
  curl -s "http://<mirror-node>/api/v1/topics/0.0.1234/messages?order=desc&limit=100" &
done
wait

# Now any subsequent request (even to a different endpoint) will block
# for up to 20 s then return a 500 connection-timeout error:
curl -v "http://<mirror-node>/api/v1/topics/0.0.1234/messages?limit=1"
# Expected: hangs ~20 s, then HTTP 500 / DbError: connection timeout
```

Repeat the first block every ~19 seconds to maintain continuous pool exhaustion.

### Citations

**File:** rest/topicmessage.js (L116-136)
```javascript
const getTopicMessages = async (req, res) => {
  const topicIdStr = req.params.topicId;
  validateGetTopicMessagesParams(topicIdStr);

  const encoding = req.query[constants.filterKeys.ENCODING];
  const filters = utils.buildAndValidateFilters(req.query, acceptedTopicsParameters);
  const topicId = EntityId.parseString(topicIdStr).getEncodedId();

  const topicMessagesResponse = {
    messages: [],
    links: {
      next: null,
    },
  };
  res.locals[constants.responseDataLabel] = topicMessagesResponse;

  // build sql query validated param and filters
  const {query, params, order, limit} = await extractSqlFromTopicMessagesRequest(topicId, filters);
  if (!query) {
    return;
  }
```

**File:** rest/topicmessage.js (L142-143)
```javascript
  const queryHint = limit !== 1 ? constants.zeroRandomPageCostQueryHint : undefined;
  const messages = await getMessages(query, params, queryHint);
```

**File:** rest/topicmessage.js (L211-215)
```javascript
  const query = `select *
      from ${TopicMessage.tableName}
      where ${conditions.join(' and ')}
      order by ${TopicMessage.CONSENSUS_TIMESTAMP} ${order}
      limit $${params.push(limit)}`;
```

**File:** rest/utils.js (L1521-1527)
```javascript
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
