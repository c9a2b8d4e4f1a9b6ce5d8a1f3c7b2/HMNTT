### Title
Unauthenticated Alias-Lookup DoS via Unbounded Database Queries in `getAccountFromAlias()`

### Summary
`getAccountFromAlias()` in `rest/service/entityService.js` issues a live database query on every invocation with no in-function result caching and no application-level rate limiting in the REST server. An unprivileged attacker can flood the endpoint with alias-lookup requests using distinct alias values, bypassing the optional URL-keyed Redis response cache, exhausting the database connection pool, and degrading service for all users.

### Finding Description
**Code path:**

`rest/service/entityService.js`, `getAccountFromAlias()`, lines 42–53:
```js
async getAccountFromAlias(accountAlias) {
  const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
  ...
}
```
`entityFromAliasQuery` (lines 17–20):
```sql
select id from entity
where coalesce(deleted, false) <> true
  and alias = $1
```

**Root cause:** Every call to `getAccountFromAlias()` unconditionally executes a database query via `BaseService.getRows()` → `pool.queryQuietly()`. There is no memoization, no in-process cache, and no LIMIT clause on the query.

**Why existing checks fail:**

1. **Response cache** (`rest/middleware/responseCacheHandler.js`, line 54): Only active when `config.cache.response.enabled && config.redis.enabled` are both true (`rest/server.js`, line 54). This is an opt-in, infrastructure-dependent feature — disabled by default. Even when enabled, the cache key is `MD5(req.originalUrl)` (line 152 of `responseCacheHandler.js`), so each distinct alias value produces a unique cache key, trivially bypassed by rotating aliases.

2. **Auth handler** (`rest/middleware/authHandler.js`): Only enforces per-user response-size limits for authenticated users. No rate limiting of any kind for unauthenticated requests.

3. **Server middleware stack** (`rest/server.js`, lines 67–98): No rate-limiting middleware is registered. The stack is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler`. No throttle, no concurrency limiter, no IP-based rate limit.

4. **Web3 throttle** (`ThrottleManagerImpl.java`): Applies only to the separate `web3` contract-call service, not the REST API.

**Exploit flow:** Attacker → `GET /api/v1/accounts/<alias_N>` with N rotating alias values → each request misses the URL cache → `getAccountFromAlias()` fires `entityFromAliasQuery` against the DB → DB connection pool saturated → legitimate requests queue/timeout.

### Impact Explanation
The database connection pool is a finite shared resource. Under sustained alias-flood traffic with rotating alias values, every concurrent request holds a pool connection for the duration of the query. Once the pool is exhausted, all other API endpoints that share the same pool (accounts, transactions, tokens, etc.) begin queuing or returning errors. The alias column is indexed (confirmed in `V2.0.3__index_init.sql`), so individual query CPU cost is low, but connection-pool exhaustion and cumulative I/O pressure at scale degrade the entire service. No authentication or special privilege is required to trigger this path.

### Likelihood Explanation
The endpoint is publicly reachable with no credential requirement. A single attacker with a modest HTTP flood tool (e.g., `wrk`, `ab`, or a simple async script) can generate thousands of requests per second. Rotating the alias parameter in each request is trivial and defeats the URL-keyed cache. The attack is repeatable, requires no exploit chain, and is effective even against a single-node deployment.

### Recommendation
1. **Application-level rate limiting**: Add a per-IP rate-limit middleware (e.g., `express-rate-limit`) to `rest/server.js` before the route handlers, unconditionally, regardless of Redis availability.
2. **In-function result caching**: Introduce a short-lived (e.g., 5–10 s) in-process LRU cache keyed on the alias value inside `getAccountFromAlias()` to absorb repeated lookups for the same alias without hitting the DB.
3. **Make response cache non-optional**: Treat Redis-backed response caching as a required component rather than an opt-in feature, or provide a fallback in-process cache.
4. **Connection pool limits with timeouts**: Configure the Postgres pool with a hard `max` connection count and a short `connectionTimeoutMillis` so that pool exhaustion returns a fast 503 rather than hanging indefinitely.

### Proof of Concept
```bash
# Generate 10,000 requests with distinct alias values, 100 concurrent
seq 1 10000 | xargs -P 100 -I{} \
  curl -s "https://<mirror-node-host>/api/v1/accounts/0.0.ALIAS{}" -o /dev/null

# Observe: DB connection pool metrics spike, legitimate requests begin timing out
# No authentication header required
```