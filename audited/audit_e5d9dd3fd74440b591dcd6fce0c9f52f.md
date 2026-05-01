### Title
Unauthenticated Connection Pool Exhaustion DoS via Concurrent Token List Requests

### Summary
The REST API's shared `pg` connection pool is configured with `max=10` and no per-client rate limiting or queue depth cap. An unauthenticated attacker sending 10 concurrent `GET /api/v1/tokens` requests with slow-running filters (e.g., `name` ILIKE wildcard) can hold all pool connections for up to `statement_timeout` (20 000 ms). Because the pool queue is unbounded beyond `connectionTimeoutMillis` (20 000 ms), every subsequent API request across all endpoints — accounts, transactions, contracts, etc. — fails with a connection-timeout error until the slow queries complete.

### Finding Description

**Pool configuration** (`rest/dbpool.js` lines 7–16):
```js
const poolConfig = {
  connectionTimeoutMillis: config.db.pool.connectionTimeout,  // default 20 000 ms
  max: config.db.pool.maxConnections,                         // default 10
  statement_timeout: config.db.pool.statementTimeout,         // default 20 000 ms
};
```
No `idleTimeoutMillis`, no queue-depth cap, no per-IP connection limit is set.

**Request handler** (`rest/tokens.js` lines 360–397):
```js
const getTokensRequest = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedTokenParameters, validateTokenQueryFilter);
  // ... builds SQL ...
  const rows = await getTokens(query, params);   // → pool.queryQuietly()
```

**Query execution** (`rest/utils.js` line 1520):
```js
result = await this.query(query, params);   // holds a pool connection for full query duration
```

The `name` filter path (`rest/tokens.js` line 177) generates:
```sql
t.name ILIKE $N   -- with value '%<attacker-string>%'
```
This is a sequential scan on the `token` table. On a large dataset this query runs for seconds. The `symbol` filter similarly uses an unindexed column comparison.

**No rate limiting exists** in `rest/server.js`. The middleware stack is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler → routes`. There is no `express-rate-limit` or equivalent layer.

**During a network partition** the situation is worse: `statement_timeout` is a server-side PostgreSQL signal. If the network is partitioned, the server cannot deliver the cancellation to the client. The `pg` driver has no client-side query timeout configured, so connections hang until OS TCP keepalive fires (minutes to hours by default), far exceeding the 20 s assumed by the question.

**Exploit flow:**
1. Attacker sends 10 concurrent `GET /api/v1/tokens?name=a&limit=100` (or any slow filter).
2. Each request calls `pool.query()`, acquiring one of the 10 pool connections.
3. Each query runs for up to `statement_timeout` (20 s) — or indefinitely during a partition.
4. Pool is fully saturated (`pool.totalCount === 10`, `pool.idleCount === 0`).
5. Any new request to any endpoint (accounts, transactions, contracts, etc.) enters the pool wait queue.
6. After `connectionTimeoutMillis` (20 000 ms) the queued request throws `Error: timeout exceeded when trying to connect`.
7. The API returns 500 to all users for the entire 20 s window, which the attacker can sustain continuously by re-issuing the 10 requests as each batch completes.

### Impact Explanation
Complete denial of service for the entire REST API — not just the tokens endpoint. All endpoints share the single global `pool` object (`global.pool` set in `rest/dbpool.js` line 36, consumed by every handler). Legitimate users receive HTTP 500 errors for the full attack duration. The attacker needs no credentials, no special network position, and no knowledge of the data schema beyond the publicly documented `name` query parameter.

### Likelihood Explanation
The attack requires only a standard HTTP client capable of 10 concurrent requests — trivially achievable with `curl`, `ab`, `wrk`, or a short script. The endpoint is public, unauthenticated, and documented in the OpenAPI spec. The `name` ILIKE filter is explicitly supported and documented. The attacker can sustain the DoS indefinitely by looping the 10-request batch. No exploit code, no vulnerability in a dependency, and no privileged access are required.

### Recommendation
1. **Add a per-IP (or global) rate limiter** before route handlers using `express-rate-limit` or an equivalent, limiting concurrent or per-second requests to the tokens endpoint.
2. **Set a client-side query timeout** in `queryQuietly` using `pg`'s `query_timeout` option or a `SET LOCAL statement_timeout` per-query hint, so the Node.js driver cancels hung queries independently of the server.
3. **Increase `max` connections** or, preferably, **add a pool queue depth cap** (`pg-pool` supports `allowExitOnIdle` and third-party wrappers support queue limits) so that pool exhaustion fails fast rather than queuing for 20 s.
4. **Add a TCP socket timeout** on the `pg` client (`connectionTimeoutMillis` covers connection establishment only; a separate `query_timeout` or `socket_timeout` is needed for in-flight queries during network partitions).

### Proof of Concept
```bash
# Exhaust all 10 pool connections with slow ILIKE scans
for i in $(seq 1 10); do
  curl -s "http://<host>:5551/api/v1/tokens?name=a&limit=100" &
done

# Immediately probe a different endpoint — will timeout after connectionTimeoutMillis (20 s)
curl -v "http://<host>:5551/api/v1/transactions"
# Expected: HTTP 500, "Error: timeout exceeded when trying to connect"
```
Repeat the first block in a loop to sustain the DoS continuously.