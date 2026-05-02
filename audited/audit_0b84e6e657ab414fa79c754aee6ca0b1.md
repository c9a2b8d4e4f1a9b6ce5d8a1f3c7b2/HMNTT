### Title
Connection Pool Exhaustion via Unauthenticated Concurrent GET /accounts Requests

### Summary
The `getAccounts()` handler in `rest/accounts.js` issues an expensive multi-table PostgreSQL query via `pool.queryQuietly()` on every request with no application-level rate limiting or concurrency cap. The default pool size is only 10 connections and the statement timeout is 20 seconds, meaning an unauthenticated attacker sending 10+ concurrent requests with `limit=100` can saturate all pool connections, causing subsequent legitimate requests to queue and eventually fail with a `DbError` (500/503-equivalent).

### Finding Description

**Code path:**

`getAccounts()` in `rest/accounts.js` (lines 335–388) calls `utils.parseLimitAndOrderParams()` which caps the limit at `responseLimit.max` (default **100**), then builds and executes a query via:

```js
// rest/accounts.js line 367
const result = await pool.queryQuietly(query, params, preQueryHint);
``` [1](#0-0) 

The generated query joins `entity`, `entity_stake`, and `token_account` (via a CTE `latest_token_balance`) — a non-trivial multi-table scan even with indexes.

**`queryQuietly` connection acquisition** (`rest/utils.js` lines 1518–1527):

- Without `preQueryHint` (standard path): calls `this.query()`, which acquires a pool connection for the full duration of query execution.
- With `preQueryHint` (public-key filter path, line 366): calls `client = await this.connect()` explicitly, holding the connection across `BEGIN`, the query, and `COMMIT` — even longer. [2](#0-1) 

**Pool configuration defaults** (`docs/configuration.md`):
- `hiero.mirror.rest.db.pool.maxConnections` = **10**
- `hiero.mirror.rest.db.pool.statementTimeout` = **20000 ms** (20 s)
- `hiero.mirror.rest.db.pool.connectionTimeout` = **20000 ms** [3](#0-2) 

**Pool initialization** (`rest/dbpool.js` lines 7–16) directly maps these to `pg.Pool`: [4](#0-3) 

**No application-level rate limiting exists** for the REST API accounts endpoint. The middleware stack (`rest/middleware/`) contains `authHandler`, `metricsHandler`, `openapiHandler`, `requestHandler`, `requestNormalizer`, `responseCacheHandler`, `responseHandler` — none implement per-IP or global concurrency throttling for this endpoint.



The Traefik `inFlightReq` / `rateLimit` middleware is only configured in the Helm charts for the Rosetta and GraphQL services, not for the REST API. [5](#0-4) 

**Exploit flow:**
1. Attacker sends 10 concurrent `GET /api/v1/accounts?limit=100` requests (no auth required).
2. Each request acquires one of the 10 pool connections and runs a slow multi-table query (up to 20 s).
3. All 10 connections are occupied simultaneously.
4. The 11th+ request enters the `pg` pool queue and waits up to `connectionTimeoutMillis` (20 s).
5. After 20 s, the waiting request throws a `DbError`, resulting in a 500 error to the client.
6. By continuously recycling 10 concurrent requests, the attacker maintains pool saturation indefinitely.

**Why existing checks fail:**
- `statementTimeout` (20 s) only limits individual query duration; it does not prevent 10 simultaneous slow queries from holding all connections.
- `limit` cap (100) reduces result size but does not prevent expensive full-table scans on large datasets.
- `connectionTimeout` (20 s) causes waiting requests to fail rather than queue indefinitely, but this is the DoS outcome itself.
- The `getLimitParamValue()` cap is a data-size guard, not a concurrency guard. [6](#0-5) 

### Impact Explanation
With the default pool of 10 connections, an attacker can render the entire REST API unavailable to legitimate users. All endpoints share the same `global.pool`, so exhaustion from `/accounts` affects `/transactions`, `/balances`, and all other endpoints. The `DbError` thrown propagates as a 500 response. This is a complete availability denial for the duration of the attack with no self-recovery until the attacker stops.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only a basic HTTP client capable of concurrent requests (e.g., `ab -c 10 -n 10000`, `wrk`, or a simple script). The default pool size of 10 is extremely small. The attack is trivially repeatable and sustainable from a single IP or distributed across multiple IPs to bypass any IP-based infrastructure rate limiting. The public-key filter path (`?account.publickey=...`) makes it even easier since connections are held longer due to the explicit `client.connect()` + transaction pattern.

### Recommendation
1. **Add application-level concurrency limiting**: Use a semaphore or middleware (e.g., `express-rate-limit`, `bottleneck`) to cap concurrent in-flight DB queries per IP and globally before they reach `pool.queryQuietly()`.
2. **Increase default pool size**: Raise `maxConnections` to a value proportional to expected concurrent load (e.g., 50–100), and configure pgBouncer in front of PostgreSQL (already present in the Helm chart for production but not enforced by default).
3. **Add Traefik `inFlightReq` middleware** to the REST API Helm chart, mirroring the pattern already used for Rosetta/GraphQL.
4. **Reduce `statementTimeout`** for the accounts endpoint to limit how long each connection is held.
5. **Add Redis response caching** (already supported via `hiero.mirror.rest.cache.response.enabled`) for the accounts list endpoint to serve repeated identical queries without hitting the DB.

### Proof of Concept
```bash
# Saturate the 10-connection pool with concurrent requests
# Run from any machine with no credentials required
for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>/api/v1/accounts?limit=100" &
done
wait

# Simultaneously, legitimate requests will receive 500 errors:
curl -v "http://<mirror-node-host>/api/v1/accounts?limit=1"
# Expected: HTTP 500 with DbError after connectionTimeout (20s)

# For sustained attack (keeps pool saturated continuously):
wrk -t10 -c10 -d60s "http://<mirror-node-host>/api/v1/accounts?limit=100"
```

### Citations

**File:** rest/accounts.js (L363-367)
```javascript
  // Execute query
  // set random_page_cost to 0 to make the cost estimation of using the index on (public_key, index)
  // lower than that of other indexes so pg planner will choose the better index when querying by public key
  const preQueryHint = pubKeyQuery.query !== '' && constants.zeroRandomPageCostQueryHint;
  const result = await pool.queryQuietly(query, params, preQueryHint);
```

**File:** rest/utils.js (L544-553)
```javascript
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
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

**File:** charts/hedera-mirror-rest/values.yaml (L1-1)
```yaml
# SPDX-License-Identifier: Apache-2.0
```
