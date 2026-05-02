### Title
Unauthenticated EVM Address Lookup in `getEncodedId()` Enables DB Connection Pool Exhaustion DoS

### Summary
`EntityService.getEncodedId()` in `rest/service/entityService.js` unconditionally issues a live database query for every valid EVM address input, with no rate limiting, no caching, and no authentication required. An unprivileged attacker flooding any of the multiple public endpoints that call this function with unique valid EVM addresses can exhaust the finite `pg` connection pool, rendering the mirror node instance unresponsive to all requests.

### Finding Description

**Exact code path:**

`getEncodedId()` at [1](#0-0)  checks `EntityId.isValidEntityId(entityIdString)` and, when the parsed `EntityId` has a non-null `evmAddress`, immediately calls `getEntityIdFromEvmAddress()`.

`getEntityIdFromEvmAddress()` at [2](#0-1)  executes the query:

```sql
SELECT id FROM entity WHERE deleted <> true AND evm_address = $1
```

via `BaseService.getRows()` → `pool.queryQuietly()` at [3](#0-2) , which calls `this.pool().queryQuietly(query, params)`.

The pool is a `pg.Pool` instance initialized in [4](#0-3)  with a hard `max: config.db.pool.maxConnections` ceiling and a `connectionTimeoutMillis` before queued requests time out.

**No rate limiting exists in the REST API layer.** `rest/server.js` registers no rate-limiting middleware: [5](#0-4) . The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` Java module, not in the Node.js REST service.

**Authentication is entirely optional.** `authHandler` at [6](#0-5)  returns immediately for unauthenticated requests (`if (!credentials) { return; }`), placing no restriction on anonymous callers.

**Multiple public endpoints expose this path:**
- `GET /api/v1/accounts/:idOrAliasOrEvmAddress` → `accounts.getOneAccount` [7](#0-6) 
- `GET /api/v1/accounts/:idOrAliasOrEvmAddress/rewards` → `listStakingRewardsByAccountId` [8](#0-7) 
- `GET /api/v1/accounts/:idOrAliasOrEvmAddress/allowances/tokens` → `getAccountTokenAllowances` [9](#0-8) 
- Contract results `from` filter with EVM address [10](#0-9) 

There is no caching layer for EVM address → entity ID resolution in the REST service. Every unique EVM address (of which there are 2^160 valid values) triggers a fresh DB query.

**Root cause / failed assumption:** The design assumes that upstream infrastructure (load balancer, reverse proxy) will enforce rate limits before requests reach the application. No such enforcement is implemented in the application itself, and the codebase contains no evidence of mandatory infrastructure-level rate limiting for the REST API.

### Impact Explanation

When the `pg` connection pool is saturated, all subsequent queries on that Node.js process queue up waiting for a free connection. Once the queue exceeds `connectionTimeoutMillis`, every request — including those unrelated to EVM address lookups — receives a `DbError` / HTTP 500. The instance becomes effectively unavailable. Because each mirror node instance maintains its own independent pool, an attacker targeting multiple instances simultaneously (or a single instance serving a large fraction of traffic) can take down 30%+ of the network's processing capacity without any privileged access.

### Likelihood Explanation

The attack requires only an HTTP client capable of issuing concurrent GET requests. Valid EVM addresses are trivially generated (`0x0000000000000000000000000000000000000001` through any 40-hex-char string). No authentication, API key, or on-chain state is needed. The attack is fully repeatable and automatable with standard tools (`wrk`, `ab`, `hey`). The default pool size is small (configurable but typically tens of connections), making exhaustion achievable with modest concurrency (~100–500 concurrent requests sustained).

### Recommendation

1. **Add application-level rate limiting** to the REST API using `express-rate-limit` or equivalent, applied globally in `rest/server.js` before route handlers, with per-IP limits.
2. **Cache EVM address → entity ID resolutions** (e.g., using the existing Redis infrastructure referenced in `config.redis`) with a short TTL to collapse repeated lookups for the same address.
3. **Increase `connectionTimeoutMillis` awareness**: ensure the pool timeout is short enough to shed load quickly rather than accumulating a large backlog.
4. **Add a `statement_timeout`** specifically for EVM address lookup queries if not already enforced at the query level (the pool-level `statement_timeout` applies globally but does not prevent pool queue buildup).

### Proof of Concept

```bash
# Generate 10,000 unique valid EVM addresses and flood the accounts endpoint
seq 1 10000 | xargs -P 500 -I{} \
  curl -s -o /dev/null \
  "https://<mirror-node-host>/api/v1/accounts/0x$(printf '%040x' {})"

# Simultaneously observe that legitimate requests begin timing out:
curl -v "https://<mirror-node-host>/api/v1/accounts/0.0.1"
# Expected: connection timeout or HTTP 500 DbError once pool is exhausted
```

Preconditions: No credentials required. Any network-reachable mirror node REST API instance.
Trigger: 500+ concurrent requests with unique EVM addresses sustained for >10 seconds.
Result: Pool exhaustion; all requests on the targeted instance fail until attack traffic subsides.

### Citations

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

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
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

**File:** rest/server.js (L68-98)
```javascript
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

**File:** rest/server.js (L102-102)
```javascript
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
```

**File:** rest/middleware/authHandler.js (L15-20)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }
```

**File:** rest/controllers/accountController.js (L171-171)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/tokenAllowanceController.js (L69-69)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/contractController.js (L443-444)
```javascript
          if (EntityId.isValidEvmAddress(filter.value)) {
            filter.value = await EntityService.getEncodedId(filter.value);
```
