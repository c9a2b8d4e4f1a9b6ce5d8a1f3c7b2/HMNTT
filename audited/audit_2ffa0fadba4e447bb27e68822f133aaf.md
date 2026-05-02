### Title
Unauthenticated EVM Address Lookup Exhausts DB Connection Pool via `/accounts/:idOrAliasOrEvmAddress/nfts`

### Summary
The `getNftsByAccountId()` handler unconditionally issues a database query for every EVM address parameter without any rate limiting, caching of lookup results, or concurrency control. The REST API's connection pool defaults to only 10 connections, so a flood of concurrent requests with unique EVM addresses saturates the pool and starves all other database-dependent endpoints of connections, causing total service unavailability.

### Finding Description

**Exact code path:**

`rest/controllers/accountController.js` line 91 — `getNftsByAccountId()` calls `EntityService.getEncodedId()` unconditionally on every request:

```js
getNftsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

`rest/service/entityService.js` lines 118–124 — `getEncodedId()` detects an EVM address and always calls `getEntityIdFromEvmAddress()`:

```js
async getEncodedId(entityIdString, ...) {
  if (EntityId.isValidEntityId(entityIdString)) {
    const entityId = EntityId.parseString(entityIdString, {paramName});
    return entityId.evmAddress === null
      ? entityId.getEncodedId()
      : await this.getEntityIdFromEvmAddress(entityId, requireResult); // DB hit
```

`rest/service/entityService.js` lines 90–91 — `getEntityIdFromEvmAddress()` issues a live database query on every call with no result caching:

```js
async getEntityIdFromEvmAddress(entityId, requireResult = true) {
  const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**Root cause — failed assumption:** The code assumes that EVM address lookups are cheap and infrequent. There is no caching of the DB lookup result in `entityService.js` (the `quickLru` cache in `entityId.js` lines 301–304 only caches the *parsed* `EntityId` object, not the DB-resolved numeric ID; `getEntityIdFromEvmAddress()` is still called every time `evmAddress !== null`). There is no rate limiting on this endpoint.

**Connection pool:** `rest/dbpool.js` lines 13–14 configure the pool from `config.db.pool`:

```js
connectionTimeoutMillis: config.db.pool.connectionTimeout,  // default 20 000 ms
max: config.db.pool.maxConnections,                         // default 10
```

The documented default is **10 connections** (`hiero.mirror.rest.db.pool.maxConnections = 10`).

**No rate limiting on the REST API:** `rest/routes/accountRoute.js` line 15 registers the route with no middleware:

```js
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

The throttling found in the codebase (`ThrottleConfiguration`, `ThrottleManagerImpl`) applies exclusively to the **web3 API**. The Traefik `inFlightReq`/`rateLimit` middleware found in the Helm charts applies only to the Rosetta API chart, not the REST API chart.

**Exploit flow:**
1. Attacker sends ≥10 concurrent `GET /accounts/0x<unique_random_40hex>/nfts` requests.
2. Each request passes `EntityId.isValidEntityId()` (valid 40-char hex), reaches `getEntityIdFromEvmAddress()`, and acquires a DB connection.
3. With 10 connections held, the 11th request blocks waiting for a free connection (up to `connectionTimeout` = 20 s).
4. Attacker sustains the flood; all 10 connections are perpetually occupied by attacker queries.
5. Every other endpoint that needs a DB connection (`/transactions`, `/balances`, `/contracts`, etc.) queues behind attacker requests and times out after 20 s, returning errors to legitimate users.

### Impact Explanation
Total service unavailability for all REST API endpoints that require database access. The mirror node cannot confirm new transactions or serve any data. The default pool size of 10 makes this trivially achievable — only 10 concurrent HTTP connections from the attacker are needed to fully saturate the pool. The `statementTimeout` of 20 s limits individual query duration but does not prevent pool exhaustion; the attacker simply re-issues requests as connections are released.

### Likelihood Explanation
No authentication, API key, or credential is required. Any internet-accessible mirror node deployment is exposed. The attacker needs only a basic HTTP client capable of maintaining concurrent connections (e.g., `ab`, `wrk`, or a simple script). The attack is repeatable indefinitely and requires no special knowledge beyond the public OpenAPI spec, which documents the EVM address path parameter format.

### Recommendation
1. **Add per-IP rate limiting** to the REST API at the application or ingress layer (e.g., Traefik `inFlightReq` + `rateLimit` middleware, mirroring what is already done for the Rosetta chart).
2. **Cache EVM address → entity ID lookups** in `EntityService.getEntityIdFromEvmAddress()` using the existing `entityId` cache infrastructure (already configured with `maxAge=1800`, `maxSize=100000`) so repeated or concurrent lookups for the same address do not each consume a DB connection.
3. **Increase the default pool size** or add a per-endpoint concurrency limit so a single endpoint cannot monopolize all connections.
4. **Return 404 immediately** (without a DB round-trip) for EVM addresses that are structurally valid but obviously synthetic (e.g., all-zero addresses), where possible.

### Proof of Concept
```bash
# Requires: wrk or parallel curl
# Flood with unique EVM addresses to bypass any parse-level cache

for i in $(seq 1 500); do
  ADDR=$(openssl rand -hex 20)
  curl -s "http://<mirror-node-host>:5551/api/v1/accounts/0x${ADDR}/nfts" &
done
wait

# Simultaneously, observe that legitimate requests time out:
curl -v "http://<mirror-node-host>:5551/api/v1/transactions"
# Expected: connection timeout or 500 after ~20 seconds
```

With 10 concurrent attacker requests sustained, the pool is fully occupied. All other API calls queue for up to 20 seconds and then fail, producing total service unavailability for legitimate consumers. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rest/controllers/accountController.js (L90-91)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/service/entityService.js (L90-91)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**File:** rest/service/entityService.js (L118-124)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** rest/routes/accountRoute.js (L15-15)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** rest/entityId.js (L301-304)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});
```
