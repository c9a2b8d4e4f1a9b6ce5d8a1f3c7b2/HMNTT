All technical claims in the report have been verified against the actual source code. Here is the result:

---

# Audit Report

## Title
Cache Stampede / Thundering Herd in `getCachedTokens()` Exhausts DB Connection Pool

## Summary
`getCachedTokens()` in `rest/service/tokenService.js` has no in-flight deduplication. Because `await super.getRows(...)` yields the Node.js event loop before the cache is populated, N concurrent requests for the same uncached token ID each independently observe a cache miss and each issue a separate DB query. This can exhaust the finite DB connection pool, causing timeouts for all other users.

## Finding Description

The vulnerable function is `getCachedTokens()` at lines 136–161 of `rest/service/tokenService.js`.

**Cache-miss check (lines 139–146):** [1](#0-0) 

All N concurrent coroutines that arrive before any one completes will each push the same token ID into `uncachedTokenIds`.

**Await that yields the event loop (line 152):** [2](#0-1) 

`await` suspends the current coroutine and returns control to the event loop, allowing all other pending coroutines to run. Each independently reaches line 152 and issues its own DB query.

**Cache population — too late for concurrent callers (lines 153–158):** [3](#0-2) 

The cache is only populated after the `await` resolves, which is after all concurrent callers have already passed the cache-miss check.

**`super.getRows` acquires a pool connection (baseService.js line 55–56):** [4](#0-3) 

**Pool is finite (dbpool.js line 14):** [5](#0-4) 

**Why existing checks fail:**
- `putTokenCache` has a `tokenCache.has()` guard but is a completely separate code path not used inside `getCachedTokens`: [6](#0-5) 
- `server.js` has no rate-limiting middleware — only cors, compression, logging, auth, metrics, and response caching are registered: [7](#0-6) 

## Impact Explanation
The DB connection pool is bounded by `config.db.pool.maxConnections`. If N concurrent requests each hold a pool connection waiting for the same token query, the pool is exhausted. All subsequent queries from any user — including unrelated endpoints — block until `connectionTimeoutMillis` elapses, at which point they receive a timeout error. This is a denial-of-service against the entire REST API.

## Likelihood Explanation
Any unauthenticated user can trigger this. The attack surface is confirmed at `tokens.js` line 726, where `getTokenBalances` calls `TokenService.getCachedTokens` with a single token ID: [8](#0-7) 

This endpoint is registered publicly at `/api/v1/tokens/:tokenId/balances`: [9](#0-8) 

The attack requires only firing N concurrent HTTP GET requests to this endpoint for a token ID not yet in the LRU cache. The cache is per-process and in-memory, so a process restart or LRU eviction resets it. Valid token IDs are publicly enumerable from the API itself.

## Recommendation
Implement **in-flight deduplication** (promise coalescing) for `getCachedTokens`. Before issuing a DB query, check a `Map<tokenId, Promise>` of in-progress fetches. If a promise already exists for a given token ID, await it instead of issuing a new query. Only create a new DB query promise if none is in flight, and remove it from the map once it resolves. This ensures N concurrent cache misses for the same token ID result in exactly one DB query.

## Proof of Concept

```js
// Attacker script — fires N concurrent requests before any one completes
const TOKEN_ID = '0.0.12345'; // any valid, currently-uncached token ID
const N = 50; // adjust to exceed pool.maxConnections

await Promise.all(
  Array.from({length: N}, () =>
    fetch(`https://target/api/v1/tokens/${TOKEN_ID}/balances`)
  )
);
// Each of the N requests independently calls getCachedTokens(),
// observes a cache miss, and issues super.getRows() concurrently,
// acquiring N pool connections simultaneously.
// All subsequent requests to any endpoint time out.
```

### Citations

**File:** rest/service/tokenService.js (L121-129)
```javascript
  putTokenCache(token) {
    const tokenId = token.token_id;
    if (tokenCache.has(tokenId)) {
      return;
    }

    const cachedToken = new CachedToken(token);
    tokenCache.set(tokenId, cachedToken);
  }
```

**File:** rest/service/tokenService.js (L139-146)
```javascript
    tokenIds.forEach((tokenId) => {
      const cachedToken = tokenCache.get(tokenId);
      if (cachedToken) {
        cachedTokens.set(tokenId, cachedToken);
      } else {
        uncachedTokenIds.push(tokenId);
      }
    });
```

**File:** rest/service/tokenService.js (L152-152)
```javascript
    const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
```

**File:** rest/service/tokenService.js (L153-158)
```javascript
    rows.forEach((row) => {
      const tokenId = row.token_id;
      const cachedToken = new CachedToken(row);
      tokenCache.set(tokenId, cachedToken);
      cachedTokens.set(tokenId, cachedToken);
    });
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

**File:** rest/server.js (L121-121)
```javascript
app.getExt(`${apiPrefix}/tokens/:tokenId/balances`, tokens.getTokenBalances);
```

**File:** rest/tokens.js (L724-727)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length > 0) {
    const cachedTokens = await TokenService.getCachedTokens(new Set([tokenId]));
    const decimals = cachedTokens.get(tokenId)?.decimals ?? null;
```
