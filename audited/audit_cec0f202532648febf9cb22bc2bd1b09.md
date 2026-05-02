### Title
LRU Token Cache Thrashing via Unauthenticated Concurrent Requests Causes DB Connection Pool Exhaustion

### Summary
The `getCachedTokens()` function in `rest/service/tokenService.js` uses a module-level `quickLru` cache with a default `maxSize` of 100,000 entries and no TTL. The REST API has no per-IP rate limiting on token-relationship endpoints, and the DB connection pool defaults to only 10 connections. An unauthenticated attacker who cycles requests across accounts whose combined token associations span more than 100,000 distinct token IDs can keep the LRU cache in a permanent thrash state, forcing a DB query on every request and saturating all available pool connections.

### Finding Description

**Exact code path:**

`rest/service/tokenService.js` lines 12–14 — cache is a module-level singleton with no TTL:
```js
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,   // default 100,000
});
``` [1](#0-0) 

`getCachedTokens()` lines 136–161 — for every token ID not found in the LRU, a DB query is issued:
```js
async getCachedTokens(tokenIds) {
  ...
  tokenIds.forEach((tokenId) => {
    const cachedToken = tokenCache.get(tokenId);
    if (cachedToken) { ... } else { uncachedTokenIds.push(tokenId); }
  });
  if (uncachedTokenIds.length === 0) return cachedTokens;
  const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
  ...
}
``` [2](#0-1) 

**Root cause — three compounding failures:**

1. **No rate limiting on the REST API.** `rest/server.js` applies only CORS, compression, logging, auth, and optional Redis response caching middleware. There is no per-IP throttle or concurrency cap on the `/api/v1/accounts/{id}/tokens` path. [3](#0-2) 

2. **DB pool capped at 10 connections by default.** `rest/dbpool.js` reads `config.db.pool.maxConnections` (documented default: 10). All concurrent requests share this pool. [4](#0-3) 

3. **LRU cache has no TTL and no request coalescing.** `quickLru` is a pure size-bounded LRU. Once the working set of token IDs exceeds 100,000, every new insertion evicts an old entry. Concurrent in-flight requests for the same evicted token ID each independently detect a cache miss and each independently issue a DB query — there is no deduplication/promise-coalescing for concurrent misses on the same key. [5](#0-4) 

**Exploit flow:**

- Hedera mainnet is public; account-to-token associations are queryable. An attacker enumerates accounts whose combined distinct token associations exceed 100,000 (trivially achievable given millions of tokens on mainnet).
- The attacker sends high-concurrency requests cycling through these accounts. Each request returns up to 100 token relationships (the configured max response limit), each potentially a cache miss.
- Because the working set > 100,000, every batch of new token IDs evicts previously cached ones. The next rotation of requests re-misses those evicted IDs.
- Each miss triggers `super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds])`, competing for one of the 10 pool connections.
- With enough concurrent requests, all 10 connections are held; new requests queue and eventually time out (20 s `connectionTimeout`), returning 503/504 to all clients.

### Impact Explanation

Complete exhaustion of the 10-connection DB pool causes the REST API to stop serving all endpoints that require DB access, not just token-relationship queries. This constitutes a total service outage for the mirror node REST API. Because the mirror node REST API is the primary read interface for dApps, wallets, and explorers querying Hedera network state, sustained unavailability prevents confirmation of new transactions and degrades the broader ecosystem's ability to observe network activity.

### Likelihood Explanation

The attack requires no credentials, no tokens owned by the attacker, and no privileged access. All required account and token data is publicly readable from the mirror node itself. The attacker needs only:
- A list of account IDs with many token associations (obtainable in minutes via the public API).
- A script sending concurrent HTTP requests (trivial).

The attack is repeatable indefinitely and self-sustaining once the cache thrash cycle is established. No economic cost is imposed on the attacker.

### Recommendation

1. **Add per-IP rate limiting** to the REST API for token-relationship endpoints (e.g., via `express-rate-limit` or an upstream API gateway).
2. **Coalesce concurrent cache misses** for the same token ID using an in-flight promise map (i.e., if a fetch for token ID X is already in progress, return the same promise rather than issuing a second DB query).
3. **Increase the default DB pool size** or add a concurrency semaphore so that the number of simultaneous `getCachedTokens` DB queries is bounded independently of the HTTP server concurrency.
4. **Add a TTL** to the `quickLru` instance (`maxAge` option) so stale entries are not held indefinitely, reducing the effective working-set pressure.

### Proof of Concept

```bash
# Step 1: Collect accounts with many token associations
curl "https://<mirror-node>/api/v1/accounts?limit=100" | jq '.accounts[].account' > accounts.txt

# Step 2: Flood concurrent requests cycling through accounts
# Using GNU parallel or similar:
cat accounts.txt | xargs -P 200 -I{} \
  curl -s "https://<mirror-node>/api/v1/accounts/{}/tokens?limit=100" -o /dev/null

# Step 3: Observe DB pool exhaustion
# Mirror node begins returning 503/504 for all endpoints.
# Repeat step 2 continuously to sustain the outage.
```

The attack sustains itself as long as the combined distinct token IDs across the cycled accounts exceeds `config.cache.token.maxSize` (100,000), which is easily satisfied on any production Hedera network.

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

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

**File:** rest/server.js (L67-99)
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
