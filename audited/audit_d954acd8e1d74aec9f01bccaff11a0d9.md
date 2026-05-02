### Title
Unbounded Cache Key Generation via Timestamp Parameters Enables Database Connection Pool Exhaustion (DoS)

### Summary
The `cacheKeyGenerator` function in `rest/middleware/responseCacheHandler.js` derives Redis keys directly from the full request URL with no normalization or deduplication. Because the REST API applies no rate limiting to the `/api/v1/accounts/<id>/rewards` endpoint, an unauthenticated attacker can flood the service with requests carrying distinct `timestamp=gte:X` values, generating unlimited unique cache misses. Each miss falls through to the database, and with a pool capped at 10 connections, the database layer is trivially exhausted, denying service to legitimate users.

### Finding Description

**Cache key generation (no normalization):**
`rest/middleware/responseCacheHandler.js`, lines 151–153:
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
Every distinct `req.originalUrl` — including `/api/v1/accounts/0.0.1001/rewards?timestamp=gte:1`, `?timestamp=gte:2`, `?timestamp=gte:3`, … — produces a unique MD5 key. There is no request normalizer (the comment on line 149 explicitly acknowledges this is future work: *"In the future, this will utilize Edwin's request normalizer (9113)"*).

**Cache-miss path triggers DB query:**
`rest/middleware/responseCacheHandler.js`, lines 45–47:
```js
if (!cachedTtlAndValue) {
  res.locals[responseCacheKeyLabel] = responseCacheKey;
  return;   // falls through to controller → DB
}
```
Every unique key that is not in Redis causes the full controller path (`listStakingRewardsByAccountId` → `StakingRewardTransferService.getRewards`) to execute against the database.

**No rate limiting in the REST API layer:**
The throttle/rate-limit infrastructure (`ThrottleManagerImpl`, bucket4j) exists exclusively in the `web3` Java service. A `grep` across all `rest/**/*.js` files finds zero usage of `rateLimit`, `throttle`, or `express-rate-limit`. The `server.js` middleware chain (lines 67–97) registers only: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, and `responseCacheCheckHandler` — no rate limiter.

**Database connection pool cap:**
`docs/configuration.md`, line 556: `hiero.mirror.rest.db.pool.maxConnections` defaults to **10**. With 10+ concurrent cache-missing requests, the pool is saturated and all subsequent legitimate queries queue or time out (`statementTimeout: 20000 ms`).

**Redis eviction policy partially mitigates but does not prevent the attack:**
`rest/cache.js`, lines 48–49 set `maxmemory-policy` to `allkeys-lfu` (250 MB cap). LFU preferentially evicts newly-inserted low-frequency keys, so the attacker's own keys are evicted first — this reduces the "evicting legitimate cached responses" aspect. However, it does **not** prevent the DB exhaustion path: every attacker request still misses the cache and hits the database regardless of what Redis evicts afterward.

**`maxRepeatedQueryParameters` (default 100) limits params per single request** but places no bound on the number of distinct requests an attacker can send.

### Impact Explanation
- **Database connection pool exhaustion**: 10 concurrent cache-missing requests saturate the pool; legitimate staking-reward queries queue behind attacker traffic and time out after 20 seconds.
- **Amplified DB load**: Each attacker request executes a full `staking_reward_transfer` table scan with timestamp conditions.
- **Availability degradation / DoS**: Legitimate users receive 500-class errors or extreme latency while the pool is held.
- **Redis memory pressure**: 250 MB fills with single-use MD5 keys; while LFU evicts them preferentially, the churn degrades Redis pipeline efficiency and increases GC pressure.

Severity: **High** (unauthenticated, no preconditions, directly impacts availability of a financial data endpoint).

### Likelihood Explanation
- Zero authentication or privilege required.
- Timestamp values are nanosecond-precision integers; the attacker has ~10^18 distinct valid values per account.
- A single script with `async` HTTP requests can saturate the 10-connection pool in milliseconds.
- The attack is repeatable indefinitely and trivially scriptable.
- No existing application-layer control (IP block, CAPTCHA, token bucket) is present in the REST service.

### Recommendation
1. **Add a request normalizer / cache-key canonicalizer** before hashing: sort query parameters, clamp or round timestamp values to a coarse granularity (e.g., nearest second), and collapse semantically equivalent ranges. The codebase already acknowledges this gap (line 149 comment referencing issue 9113) — prioritize it.
2. **Add rate limiting middleware** to the Express REST API (e.g., `express-rate-limit` per IP) covering at minimum the `/api/v1/accounts/*/rewards` route.
3. **Enforce a `maxTimestampRange`** for the rewards endpoint (the config key already exists for other endpoints at `hiero.mirror.rest.query.maxTimestampRange`).
4. **Increase the DB connection pool** or add a request queue with a concurrency cap to prevent pool exhaustion under load.
5. Consider deploying an ingress-level rate limiter (Traefik `rateLimit` middleware is already used for the Rosetta service but not for the REST API).

### Proof of Concept
```bash
# Flood with 500 unique timestamp values, 20 concurrent
seq 1 500 | xargs -P20 -I{} curl -s \
  "https://<mirror-node>/api/v1/accounts/0.0.1001/rewards?timestamp=gte:{}" \
  -o /dev/null

# Simultaneously, measure legitimate request latency:
time curl "https://<mirror-node>/api/v1/accounts/0.0.1001/rewards"
# Expected: timeout or >20s response while pool is saturated
```

Each of the 500 requests produces a unique MD5 key (`MD5("/api/v1/accounts/0.0.1001/rewards?timestamp=gte:N") + "-v1"`), misses the cache, and issues a DB query. With 20 concurrent workers and a pool of 10, the pool is immediately exhausted and legitimate queries are denied. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/middleware/responseCacheHandler.js (L45-47)
```javascript
  if (!cachedTtlAndValue) {
    res.locals[responseCacheKeyLabel] = responseCacheKey;
    return;
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/cache.js (L47-51)
```javascript
      .on('ready', () => {
        this.#setConfig('maxmemory', redisConfig.maxMemory);
        this.#setConfig('maxmemory-policy', redisConfig.maxMemoryPolicy);
        this.ready = true;
      });
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

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** docs/configuration.md (L594-596)
```markdown
| `hiero.mirror.rest.redis.maxMemory`                                      | 250Mb                   | The maximum amount of memory that Redis should be configured to use for caching                                                                                                               |
| `hiero.mirror.rest.redis.maxMemoryPolicy`                                | allkeys-lfu             | The key eviction policy Redis should use when the max memory threshold has been reached                                                                                                       |
| `hiero.mirror.rest.redis.maxRetriesPerRequest`                           | 1                       | The maximum number of times that the Redis command should be retried                                                                                                                          |
```
