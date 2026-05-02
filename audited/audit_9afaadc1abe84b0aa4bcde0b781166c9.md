### Title
Unauthenticated Cache-Bypass DoS via Unique `topicId` Values Exhausting the DB Connection Pool on `GET /api/v1/topics/:topicId/messages`

### Summary
The `GET /api/v1/topics/:topicId/messages` endpoint in the Node.js REST API has no application-level rate limiting. The Redis response cache key is derived from the full request URL, so requests with distinct `topicId` values always produce cache misses and force a live database query each time. With the default pool capped at 10 connections and a 20-second statement timeout, a low-volume flood of requests using unique valid topic IDs can saturate the entire connection pool, rendering the REST API unable to serve any further queries until connections drain.

### Finding Description

**Route registration** — `rest/server.js` line 127:
```js
app.getExt(`${apiPrefix}/topics/:topicId/messages`, topicmessage.getTopicMessages);
```
No rate-limiting middleware is applied before or after this route. The full middleware chain in `rest/server.js` is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler → [route handler] → responseHandler → responseCacheUpdateHandler → handleError`. None of these enforce a per-IP or global request rate limit on the REST API.

**Cache key generation** — `rest/middleware/responseCacheHandler.js` line 151-152:
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
`req.originalUrl` includes the full path, so `/api/v1/topics/0.0.1/messages` and `/api/v1/topics/0.0.2/messages` produce different MD5 hashes → different cache keys → guaranteed cache miss for every unique `topicId`.

**Cache is also disabled by default** — `rest/server.js` line 54:
```js
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
```
`cache.response.enabled` defaults to `false` (docs: `hiero.mirror.rest.cache.response.enabled = false`), so in many deployments the cache layer is entirely absent.

**Each cache miss triggers a live DB query** — `rest/topicmessage.js` lines 133, 143:
```js
const {query, params, order, limit} = await extractSqlFromTopicMessagesRequest(topicId, filters);
const messages = await getMessages(query, params, queryHint);
```
`getMessages` calls `pool.queryQuietly(query, params, preQueryHint)`, which acquires a connection from the shared `pg.Pool`.

**Connection pool is tiny by default** — `rest/dbpool.js` line 14:
```js
max: config.db.pool.maxConnections,   // default: 10
```
`statementTimeout` defaults to 20 000 ms. With 10 connections and 20-second queries, an attacker needs only 10 concurrent in-flight requests to hold every connection.

**No authentication or authorization required** — `rest/middleware/authHandler.js` lines 15-19:
```js
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);
  if (!credentials) {
    return;   // anonymous requests pass through unconditionally
  }
```
Unauthenticated requests are allowed to proceed to the route handler.

**Exploit flow:**
1. Attacker sends 10+ concurrent `GET /api/v1/topics/0.0.<N>/messages` requests, incrementing `N` for each.
2. Each request misses the cache (unique URL → unique MD5 key).
3. Each request acquires one connection from the 10-connection pool and holds it for up to 20 seconds while the DB query runs.
4. Pool is saturated; subsequent requests from any client block waiting for a free connection (up to `connectionTimeoutMillis = 20 000 ms`) then fail with a connection-timeout error.
5. Attacker re-issues requests before the 20-second timeout expires, maintaining saturation indefinitely.

### Impact Explanation
The REST API becomes completely unresponsive for all endpoints (accounts, transactions, tokens, etc.) that share the same `pg.Pool`. Any monitoring or tooling that relies on the mirror node REST API to confirm transaction propagation is blinded. While the Hedera consensus network itself is unaffected, the mirror node's read path is fully denied to all users for the duration of the attack. Severity: **High** (availability impact, no authentication required, trivially repeatable).

### Likelihood Explanation
The attack requires zero privileges, zero credentials, and only a basic HTTP client capable of sending concurrent requests. Valid `topicId` values follow the simple `shard.realm.num` format (e.g., `0.0.1` through `0.0.999999`); an attacker does not need to know which topics actually exist — the handler queries the DB regardless and returns an empty result set or 404, both of which still consume a connection. The attack is fully scriptable with `curl`, `ab`, `wrk`, or any load-testing tool.

### Recommendation
1. **Add application-level rate limiting** to the Node.js REST API (e.g., `express-rate-limit` or a Traefik `rateLimit` middleware matching the Rosetta pattern already present in `charts/hedera-mirror-rosetta/values.yaml`) scoped per source IP.
2. **Increase the default pool size** or add a per-endpoint concurrency cap so a single endpoint cannot monopolize all connections.
3. **Enable the Redis response cache** by default and consider normalizing cache keys so that requests for non-existent topic IDs are also cached (short TTL negative caching) to prevent repeated DB hits for the same invalid ID.
4. **Add an in-flight request limit** (e.g., Traefik `inFlightReq`) for the REST API, analogous to the Rosetta configuration.

### Proof of Concept
```bash
# Saturate the 10-connection pool with 20 concurrent requests using unique topicIds
for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>:5551/api/v1/topics/0.0.$i/messages" &
done
wait

# All subsequent requests from any client now time out or receive connection errors:
curl -v "http://<mirror-node-host>:5551/api/v1/transactions"
# Expected: hangs for 20 seconds then fails with pool connection timeout
```
Repeat the first loop before the 20-second `statementTimeout` expires to maintain continuous saturation.