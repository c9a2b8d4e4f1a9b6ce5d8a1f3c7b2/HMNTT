### Title
Cache Stampede / Thundering Herd in `getCachedTokens()` Exhausts DB Connection Pool

### Summary
`getCachedTokens()` in `rest/service/tokenService.js` uses an in-process `quickLru` cache with no in-flight deduplication. Because `await super.getRows(...)` yields the Node.js event loop before the cache is populated, N concurrent requests for the same uncached token IDs each independently observe a cache miss and each issue a separate DB query simultaneously. This can exhaust the finite DB connection pool, causing timeouts for all other users.

### Finding Description

**Exact code path**: `rest/service/tokenService.js`, `getCachedTokens()`, lines 136–161.

```js
// lines 139–146: cache-miss check
tokenIds.forEach((tokenId) => {
  const cachedToken = tokenCache.get(tokenId);   // line 140 – cache miss
  if (cachedToken) { ... } else {
    uncachedTokenIds.push(tokenId);              // line 144 – all N requests push here
  }
});

// line 152: DB query – yields the event loop via `await`
const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);

// lines 153–158: cache is populated AFTER the await resolves
rows.forEach((row) => {
  tokenCache.set(tokenId, cachedToken);          // line 156 – too late for concurrent callers
});
```

**Root cause**: The cache check (line 140) and cache population (line 156) are separated by an `await` (line 152). Node.js is single-threaded but cooperative: `await` suspends the current coroutine and returns control to the event loop, allowing other pending coroutines to run. All N concurrent requests that arrived before any one of them completes will each independently observe a cache miss and each independently issue `super.getRows(...)`.

`super.getRows` calls `this.pool().queryQuietly(query, params)` (baseService.js line 56), which acquires a connection from the global `pg` pool configured with `max: config.db.pool.maxConnections` (dbpool.js line 14). There is no in-flight deduplication, no promise coalescing, and no per-token-ID lock.

**Why existing checks fail**:
- `putTokenCache` has a `tokenCache.has()` guard (line 123) but is a separate code path used only when listing tokens, not inside `getCachedTokens`.
- The REST API server (`server.js`) has no rate-limiting middleware; the throttling found in the codebase is exclusively in the web3 Java service.
- The `quickLru` cache itself is correct but only helps after the first request completes — it provides zero protection during the window between cache-miss detection and cache population.

### Impact Explanation
The DB connection pool is finite (`max: config.db.pool.maxConnections`). If N concurrent requests each hold a pool connection waiting for the same token query, the pool can be exhausted. Subsequent legitimate queries from any user — including unrelated endpoints — will block waiting for a connection until `connectionTimeoutMillis` elapses, at which point they receive a timeout error. This is a denial-of-service against the entire REST API with no economic cost to the attacker and no privileged access required.

### Likelihood Explanation
Any unauthenticated user can send HTTP GET requests. The attack requires only a script that fires N concurrent requests (e.g., via `Promise.all` or `curl --parallel`) to any endpoint that calls `getCachedTokens` — specifically `/api/v1/tokens/:tokenId/balances` (tokens.js line 726) or any account token-relationship endpoint (tokenService.js line 104) — for a token ID that is not yet cached. The attack is trivially repeatable: the cache is per-process and in-memory, so a process restart or LRU eviction resets it. The attacker does not need to know any secret; valid token IDs are publicly enumerable from the API itself.

### Recommendation
Introduce in-flight deduplication by storing a `Promise` in a separate `Map` keyed by the set of uncached token IDs. Before issuing a DB query, check whether an identical query is already in flight; if so, `await` the existing promise instead of issuing a new one. A minimal pattern:

```js
const inFlight = new Map(); // module-level, alongside tokenCache

async getCachedTokens(tokenIds) {
  // ... existing cache-hit logic ...

  const key = uncachedTokenIds.sort().join(',');
  if (inFlight.has(key)) {
    return inFlight.get(key); // coalesce onto the existing query
  }

  const promise = super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds])
    .then(rows => {
      rows.forEach(row => { tokenCache.set(row.token_id, new CachedToken(row)); });
      inFlight.delete(key);
      // merge and return cachedTokens map
    })
    .catch(err => { inFlight.delete(key); throw err; });

  inFlight.set(key, promise);
  return promise;
}
```

Alternatively, use a library such as `p-memoize` with a short TTL, or add an application-level rate limiter (e.g., `express-rate-limit`) to bound the number of concurrent requests per IP.

### Proof of Concept

**Preconditions**: A token with ID `0.0.500` exists in the DB but is not yet in the in-process LRU cache (e.g., fresh process start or after LRU eviction).

**Trigger**:
```bash
# Send 50 concurrent requests before any one completes and populates the cache
for i in $(seq 1 50); do
  curl -s "http://<mirror-node>/api/v1/tokens/0.0.500/balances" &
done
wait
```

**Result**: All 50 requests independently execute `SELECT decimals, freeze_status, kyc_status, token_id FROM token WHERE token_id = any ($1)` simultaneously, each holding a DB pool connection. With a default pool size smaller than 50, remaining connections are unavailable to other users. Requests to unrelated endpoints (e.g., `/api/v1/transactions`) begin timing out with `connection timeout` errors until the stampede resolves. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/service/tokenService.js (L136-161)
```javascript
  async getCachedTokens(tokenIds) {
    const cachedTokens = new Map();
    const uncachedTokenIds = [];
    tokenIds.forEach((tokenId) => {
      const cachedToken = tokenCache.get(tokenId);
      if (cachedToken) {
        cachedTokens.set(tokenId, cachedToken);
      } else {
        uncachedTokenIds.push(tokenId);
      }
    });

    if (uncachedTokenIds.length === 0) {
      return cachedTokens;
    }

    const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
    rows.forEach((row) => {
      const tokenId = row.token_id;
      const cachedToken = new CachedToken(row);
      tokenCache.set(tokenId, cachedToken);
      cachedTokens.set(tokenId, cachedToken);
    });

    return cachedTokens;
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

**File:** rest/tokens.js (L724-727)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length > 0) {
    const cachedTokens = await TokenService.getCachedTokens(new Set([tokenId]));
    const decimals = cachedTokens.get(tokenId)?.decimals ?? null;
```
