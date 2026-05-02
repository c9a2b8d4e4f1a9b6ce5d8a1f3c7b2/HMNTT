### Title
Unauthenticated Connection Pool Exhaustion via `GET /blocks/0` (No Rate Limiting + `allowZero=true` Bypasses 400 Gate)

### Summary
The `GET /blocks/:hashOrNumber` endpoint accepts block number `0` as a valid input because `validateHashOrNumber` calls `isPositiveLong(hashOrNumber, true)` with `allowZero=true`, causing every such request to acquire a database connection and execute a `SELECT … WHERE index = $1` query. The REST API has no rate-limiting middleware, and the default connection pool is capped at 10 connections. An unprivileged attacker flooding this endpoint at high concurrency can exhaust the pool, causing all subsequent legitimate requests to queue for up to 20 seconds before timing out.

### Finding Description

**Code path:**

`rest/routes/blockRoute.js:13` → `BlockController.getByHashOrNumber` (`rest/controllers/blockController.js:114-124`) → `validateHashOrNumber` (`blockController.js:28-38`) → `RecordFileService.getByHashOrNumber` (`rest/service/recordFileService.js:164-179`) → `BaseService.getSingleRow` (`rest/service/baseService.js:59-66`) → pool query.

**Root cause — `allowZero=true` bypasses the 400 gate:**

```js
// rest/controllers/blockController.js:33-34
if (utils.isPositiveLong(hashOrNumber, true)) {   // 0 passes here
  return {hash: null, number: hashOrNumber};
}
```

`isPositiveLong` with `allowZero=true` (`rest/utils.js:93-101`) accepts `"0"`. Without this flag, `"0"` would fail and return HTTP 400 before touching the database. With it, execution continues to:

```js
// rest/service/recordFileService.js:171-177
whereStatement += `${RecordFile.INDEX} = $1`;
params.push(number);                              // number = "0"
const query = `${RecordFileService.blocksQuery} where ${whereStatement}`;
const row = await super.getSingleRow(query, params);  // acquires a pool connection
return row ? new RecordFile(row) : null;
```

Every request acquires one of the 10 pool connections (`rest/dbpool.js:14`: `max: config.db.pool.maxConnections`, default `10`), executes the query, and releases it. There is **no rate-limiting middleware** in the REST API stack (`rest/server.js:68-144`): the middleware chain is `cors → compression → httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler → responseHandler → handleError`. The web3 API has `ThrottleConfiguration`/`ThrottleManagerImpl`; the Node.js REST API has none.

**Exploit flow:**

1. Attacker sends N concurrent `GET /api/v1/blocks/0` requests (no auth, no API key).
2. Each request passes `isPositiveLong("0", true)` → reaches `getByHashOrNumber(null, "0")`.
3. Each request acquires a pool connection and executes `SELECT … WHERE index = 0`.
4. With 10 connections and ~1 ms query time, the pool saturates at ~10 000 req/s — easily achievable from a single host.
5. Once saturated, new requests queue inside `pg.Pool` waiting up to `connectionTimeoutMillis: 20000` ms (`rest/dbpool.js:13`).
6. The Node.js event loop accumulates thousands of pending async contexts, growing heap memory.
7. Legitimate API users receive 20-second delays or connection-timeout errors across **all** REST endpoints sharing the same pool.

### Impact Explanation

All REST API endpoints share the same `primaryPool` (`rest/service/recordFileService.js:203-205`, `rest/service/baseService.js:96-98`). Pool exhaustion caused by flooding `/blocks/0` degrades or denies service to every other endpoint (accounts, transactions, tokens, contracts, etc.). The impact is a full REST API denial-of-service with no collateral damage to the database itself (queries are fast and bounded by `statementTimeout`). Severity: **High** (availability impact, no authentication required, no rate limit).

### Likelihood Explanation

The attack requires zero privileges, zero API keys, and no special knowledge beyond the public OpenAPI spec (`rest/api/v1/openapi.yml:441-460`). A single commodity machine with a 1 Gbps link can sustain the required request rate. The attack is trivially repeatable and scriptable (e.g., `wrk`, `ab`, `hey`). The only operational barrier is network bandwidth to the target.

### Recommendation

1. **Add rate limiting to the REST API** — apply a per-IP or global token-bucket middleware (e.g., `express-rate-limit`) to all routes, mirroring the `ThrottleConfiguration` already present in the web3 API.
2. **Increase the default pool size** or deploy PgBouncer in front of the REST API (the Helm chart already configures PgBouncer for other components at `charts/hedera-mirror/values.yaml:427-443`).
3. **Reject `0` at the validation layer** — if block 0 is not a valid production block, change `isPositiveLong(hashOrNumber, true)` to `isPositiveLong(hashOrNumber, false)` (remove `allowZero`) so `"0"` returns HTTP 400 without a DB round-trip.
4. **Add a connection-wait timeout guard** — if `pg.Pool` throws a connection-timeout error, return HTTP 503 immediately rather than propagating the error as a 500.

### Proof of Concept

```bash
# Requires: wrk (https://github.com/wg/wrk) or equivalent load tool
# Target: REST API with default pool (maxConnections=10)

# Step 1 – confirm 0 is accepted and returns 404 (not 400):
curl -s http://<mirror-node-rest>:5551/api/v1/blocks/0
# Expected: {"_status":{"messages":[{"message":"Not found"}]}} HTTP 404

# Step 2 – flood at high concurrency to exhaust the 10-connection pool:
wrk -t 8 -c 200 -d 60s http://<mirror-node-rest>:5551/api/v1/blocks/0

# Step 3 – while flood is running, observe legitimate requests timing out:
curl -s --max-time 5 http://<mirror-node-rest>:5551/api/v1/transactions
# Expected during attack: connection timeout or 20-second hang

# Step 4 – observe Node.js heap growth and pool queue depth via /swagger metrics endpoint.
```