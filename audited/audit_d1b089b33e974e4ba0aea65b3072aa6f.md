### Title
Unauthenticated Request Flood Exhausts DB Connection Pool via `/accounts/:idOrAliasOrEvmAddress/allowances/crypto`

### Summary
The REST Node.js service has no application-level rate limiting on any endpoint, including `/accounts/:idOrAliasOrEvmAddress/allowances/crypto`. An unauthenticated attacker can flood this endpoint with concurrent requests at `limit=100`, each of which acquires a connection from the shared `pg` pool and executes a full `SELECT * FROM crypto_allowance` query, exhausting the finite pool and degrading or denying service to all other API consumers.

### Finding Description

**Exact code path:**

`rest/server.js` (lines 67–98) defines the complete middleware stack: [1](#0-0) 

The stack is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler (optional) → responseCacheCheckHandler (optional) → routes`. There is no rate-limiting middleware anywhere in this chain. No `express-rate-limit` or equivalent package is imported or applied.

`rest/middleware/index.js` exports only: `authHandler`, `handleError`, `openApiValidator`, `requestLogger`, `requestQueryParser`, `responseCacheCheckHandler`, `responseCacheUpdateHandler`, `responseHandler`, `serveSwaggerDocs`. No rate limiter is present. [2](#0-1) 

The `authHandler` only sets a per-user response-size `limit` in `httpContext` for authenticated users with credentials. It does not throttle request frequency for any user, authenticated or not.

`getAccountCryptoAllowances` (lines 76–98) unconditionally calls `CryptoAllowanceService.getAccountCryptoAllowances()` for every inbound request: [3](#0-2) 

`CryptoAllowanceService.getAccountCryptoAllowances` calls `super.getRows(query, params)`: [4](#0-3) 

`BaseService.getRows` calls `pool.queryQuietly`, acquiring a connection from the shared `pg` pool: [5](#0-4) 

The pool is bounded by `config.db.pool.maxConnections`: [6](#0-5) 

**Root cause:** The application assumes infrastructure-level rate limiting (Traefik middleware templates exist in Helm charts but are operator-configured and not guaranteed). At the application layer, there is no per-IP, per-endpoint, or global request rate limit. The `statementTimeout` and `maxConnections` are the only guards, and they bound query duration and pool size respectively — they do not prevent pool saturation from concurrent requests.

**Why `limit=100` matters:** `getLimitParamValue` caps unauthenticated requests at `responseLimit.max` (default 100): [7](#0-6) 

This means each request performs a maximum-cost query (`SELECT * FROM crypto_allowance WHERE owner=$1 AND amount>0 ORDER BY spender DESC LIMIT 100`), returning up to 100 rows. An attacker deliberately uses `limit=100` to maximize per-request DB work.

**Why the response cache does not mitigate this:** The cache key is `path?query`. Rotating through different `idOrAliasOrEvmAddress` values (e.g., iterating over known account IDs) produces distinct cache keys, bypassing any cached response. [8](#0-7) 

**The throttle that exists is irrelevant here:** `ThrottleConfiguration` and `ThrottleManagerImpl` are in the `web3` Java service and apply only to EVM contract-call endpoints, not to the REST Node.js service. [9](#0-8) 

### Impact Explanation
When the attacker saturates `maxConnections` concurrent DB connections, all subsequent requests across the entire REST API (not just this endpoint) queue waiting for a free connection. Once the `connectionTimeoutMillis` elapses, requests fail with a pool timeout error, returning 500 to legitimate users. This constitutes a non-network-based DoS: the attacker does not need to saturate network bandwidth — only the DB connection pool, which is a small finite resource (default pool sizes in Node.js `pg` are typically 10). The impact is service-wide availability degradation.

### Likelihood Explanation
Preconditions: none. The endpoint is public, requires no authentication, and accepts any valid account ID format (numeric, EVM address, alias). The attacker needs only a single machine with a standard HTTP client capable of sending concurrent requests. The attack is trivially repeatable and scriptable. Rotating account IDs defeats caching. The `statementTimeout` (default varies, but queries on large datasets can approach it) means connections are held for non-trivial durations, making pool exhaustion achievable with modest concurrency (e.g., 20–50 concurrent connections against a pool of 10).

### Recommendation
1. Add an application-level rate-limiting middleware to `rest/server.js` using `express-rate-limit` (or equivalent), applied globally before route handlers, keyed on `req.ip`.
2. Set a per-IP concurrent-connection limit or a sliding-window request rate (e.g., 100 req/min per IP) as a baseline floor that applies even when Traefik is absent or misconfigured.
3. Do not rely solely on infrastructure-level controls for a defense-in-depth posture.
4. Consider adding a concurrency limiter (e.g., `p-limit` or a semaphore) around DB pool acquisition to shed load gracefully before the pool is exhausted.

### Proof of Concept
```bash
# Enumerate known account IDs (publicly available from the ledger)
# Send 200 concurrent requests, each to a different account, limit=100
seq 1 200 | xargs -P 200 -I{} curl -s \
  "https://<mirror-node-host>/api/v1/accounts/0.0.{}/allowances/crypto?limit=100" \
  -o /dev/null

# Simultaneously, observe legitimate requests failing:
curl -v "https://<mirror-node-host>/api/v1/accounts/0.0.1001/allowances/crypto"
# Expected: 500 Internal Server Error or connection timeout
# due to DB pool exhaustion
```

No credentials, special headers, or prior knowledge beyond publicly enumerable account IDs are required.

### Citations

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

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```

**File:** rest/controllers/cryptoAllowanceController.js (L76-80)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
    const {conditions, params, order, limit} = this.extractCryptoAllowancesQuery(filters, accountId);
    const allowances = await CryptoAllowanceService.getAccountCryptoAllowances(conditions, params, order, limit);
```

**File:** rest/service/cryptoAllowanceService.js (L13-16)
```javascript
  async getAccountCryptoAllowances(conditions, initParams, order, limit) {
    const {query, params} = this.getAccountAllowancesQuery(conditions, initParams, order, limit);
    const rows = await super.getRows(query, params);
    return rows.map((ca) => new CryptoAllowance(ca));
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

**File:** rest/middleware/responseCacheHandler.js (L141-155)
```javascript
/*
 * Generate the cache key to access Redis. While Accept-Encoding is specified in the API response Vary
 * header, and therefore that request header value should be used as part of the cache key, the cache
 * implementation stores the response body as the original JSON object without any encoding applied. Thus it
 * is the same regardless of the accept encoding specified, and chosen by the compression middleware.
 *
 * Current key format:
 *
 *   path?query - In the future, this will utilize Edwin's request normalizer (9113).
 */
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};

const getCacheControlExpiryOrDefault = (headerValue) => {
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
