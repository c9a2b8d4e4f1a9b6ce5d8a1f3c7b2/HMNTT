### Title
Unauthenticated DB Connection Pool Exhaustion via Alias/EVM Address Lookups on `/accounts/:idOrAliasOrEvmAddress/nfts`

### Summary
Any unauthenticated attacker can send a flood of concurrent GET requests to `/api/v1/accounts/{alias_or_evm_address}/nfts` using valid-format but non-existent alias or EVM address values. Each request unconditionally issues a live database query with no result caching, and the default DB connection pool is only 10 connections with no application-level rate limiting. Exhausting the pool causes all subsequent DB-dependent requests across the entire REST API to queue and eventually time out, rendering the mirror node REST service fully unavailable.

### Finding Description

**Exact code path:**

`rest/routes/accountRoute.js:12,15` registers the route: [1](#0-0) 

The handler `AccountController.getNftsByAccountId` immediately calls `EntityService.getEncodedId()` with the raw path parameter before any other validation: [2](#0-1) 

Inside `getEncodedId`, two branches trigger live DB queries:

1. **EVM address branch** (`EntityId.isValidEntityId` returns true for a 40-hex-char string): calls `getEntityIdFromEvmAddress()` which executes `entityFromEvmAddressQuery` unconditionally: [3](#0-2) [4](#0-3) 

2. **Alias branch** (`AccountAlias.isValid` returns true for any `[A-Z2-7]+` string): calls `getAccountIdFromAlias()` → `getAccountFromAlias()` which executes `entityFromAliasQuery` unconditionally: [5](#0-4) [6](#0-5) 

**No caching of DB results:** The `quickLru` cache in `entityId.js` only caches the parsed `EntityId` struct (shard/realm/num), not the DB lookup result. The `getEntityIdFromEvmAddress` and `getAccountIdFromAlias` methods always hit the database: [7](#0-6) 

**Root cause — tiny default pool, no rate limiting:**

The DB pool is initialized with `max: config.db.pool.maxConnections`, which defaults to **10 connections**: [8](#0-7) [9](#0-8) 

`connectionTimeout` is 20,000 ms and `statementTimeout` is 20,000 ms, meaning each connection can be held for up to 20 seconds per query.

**No application-level rate limiting:** `rest/server.js` registers no rate-limit or concurrency-limit middleware: [10](#0-9) 

The Helm chart middleware for `hedera-mirror-rest` only configures `circuitBreaker` and `retry` — no `inFlightReq` or `rateLimit`: [11](#0-10) 

Furthermore, `global.middleware` defaults to `false`, meaning even these Traefik middlewares are not applied unless explicitly enabled: [12](#0-11) 

**Alias length is unbounded:** The alias regex `accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/` imposes no upper length limit on the base32 portion: [13](#0-12) 

A maximally long alias that successfully base32-decodes passes `isValid`, enters `getAccountIdFromAlias`, and issues a DB query with a large binary parameter, potentially bypassing index efficiency.

### Impact Explanation

With only 10 DB connections and no rate limiting, an attacker holding 10 concurrent requests (each waiting up to 20 seconds for a DB response) fully exhausts the pool. All other REST API endpoints that require DB access — transactions, balances, tokens, contracts, etc. — will queue waiting for a free connection and fail with connection timeout errors after 20 seconds. This constitutes complete REST API unavailability. The `statementTimeout` of 20 seconds means each attacker request occupies a slot for up to 20 seconds, so sustaining the attack requires only ~10 concurrent HTTP connections — trivially achievable.

### Likelihood Explanation

No authentication, no rate limiting, no per-IP concurrency limit, and no application-level guard are required. Any internet-accessible mirror node deployment with default configuration is vulnerable. The attack requires only a basic HTTP client capable of sending concurrent requests (e.g., `curl`, `ab`, `wrk`). The attacker does not need to know any valid account IDs — any syntactically valid EVM address (e.g., `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`) or base32 alias string triggers the DB lookup. The attack is repeatable and requires no special knowledge of the target system.

### Recommendation

1. **Add application-level concurrency/rate limiting**: Add an `express-rate-limit` or similar middleware in `rest/server.js` before route handlers, limiting requests per IP per second.
2. **Cache DB lookup results**: Cache the result of `getEntityIdFromEvmAddress` and `getAccountIdFromAlias` (including negative/not-found results) using the existing `entityId` LRU cache or a separate cache, keyed by the input string.
3. **Enforce alias length limit**: Add a maximum length check in `AccountAlias.isValid()` (e.g., reject aliases longer than 100 characters) to prevent oversized DB parameters.
4. **Increase pool size or add pool queue limit**: Increase `maxConnections` from 10 and configure a maximum pool queue depth so that excess requests are rejected immediately (HTTP 429) rather than queued for 20 seconds.
5. **Enable Traefik `inFlightReq` middleware**: Set `global.middleware: true` and add an `inFlightReq` entry to the `hedera-mirror-rest` Helm chart middleware list, mirroring the protection already present in the Rosetta chart.

### Proof of Concept

```bash
# Send 50 concurrent requests using a valid EVM address format that doesn't exist in the DB.
# Each request triggers a live DB query. With maxConnections=10, the pool is exhausted
# after the first 10 concurrent requests; subsequent requests queue and time out.

for i in $(seq 1 50); do
  curl -s "http://<mirror-node-host>/api/v1/accounts/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/nfts" &
done
wait

# Simultaneously, verify that a legitimate request to a different endpoint is blocked:
time curl "http://<mirror-node-host>/api/v1/transactions"
# Expected: request hangs for ~20 seconds then returns a 500/503 or connection timeout error.
```

### Citations

**File:** rest/routes/accountRoute.js (L12-15)
```javascript
const getPath = (path) => `/:${filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}/${path}`;

const resource = 'accounts';
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

**File:** rest/controllers/accountController.js (L90-92)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
```

**File:** rest/service/entityService.js (L17-20)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L42-43)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
```

**File:** rest/service/entityService.js (L90-91)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**File:** rest/entityId.js (L301-304)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});
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

**File:** rest/server.js (L67-98)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** charts/hedera-mirror-rest/values.yaml (L89-89)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-rest/values.yaml (L134-139)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```

**File:** rest/accountAlias.js (L10-10)
```javascript
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
```
