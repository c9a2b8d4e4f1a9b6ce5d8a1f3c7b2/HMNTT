### Title
Unauthenticated DoS via DB Connection Pool Exhaustion on `/accounts/:idOrAliasOrEvmAddress/allowances/tokens`

### Summary
The REST Node.js service exposes `GET /api/v1/accounts/:idOrAliasOrEvmAddress/allowances/tokens` with no rate limiting middleware. Every request acquires a PostgreSQL connection from a finite pool. An unauthenticated attacker flooding this endpoint can exhaust the pool, causing connection-timeout failures across all REST API endpoints for legitimate users.

### Finding Description

**Exact code path:**

`getAccountTokenAllowances()` in `rest/controllers/tokenAllowanceController.js` lines 68–81 issues at minimum two sequential database operations per request: `EntityService.getEncodedId()` (line 69) and `TokenAllowanceService.getAccountTokenAllowances()` (line 72). [1](#0-0) 

The database pool is initialized in `rest/dbpool.js` with a hard cap of `config.db.pool.maxConnections` connections and a `connectionTimeoutMillis` before a queued request errors out. [2](#0-1) 

**Middleware stack (root cause):**

`rest/server.js` registers the full middleware chain at lines 68–98. The chain is: `urlencoded → json → cors → compression (optional) → httpContext → requestLogger → authHandler → metricsHandler (optional) → responseCacheCheckHandler (optional)`. There is no rate-limiting middleware anywhere in this chain. [3](#0-2) 

**Why existing checks are insufficient:**

- `authHandler` (lines 15–36 of `rest/middleware/authHandler.js`) only validates Basic Auth credentials and sets a per-user response-size limit. It performs no rate limiting and passes unauthenticated requests through unconditionally (line 18–19: `if (!credentials) { return; }`). [4](#0-3) 

- The `ThrottleConfiguration` / `ThrottleManagerImpl` with bucket4j rate limiting exists only in the `web3` Java module and is entirely separate from this Node.js REST service. [5](#0-4) 

- `responseCacheCheckHandler` is only active when both `config.cache.response.enabled` AND `config.redis.enabled` are true — an optional deployment feature, not a security control. [6](#0-5) 

- `statementTimeout` (pool config) limits individual query duration but does not limit the rate of incoming requests or the number of concurrent pool acquisitions. [7](#0-6) 

### Impact Explanation
Once the connection pool is exhausted, every subsequent request to any REST endpoint that requires a DB connection will block until `connectionTimeoutMillis` elapses, then return an error. This is a full denial-of-service of the entire REST API, not just the allowances endpoint. Severity is **High**: complete service unavailability for all users with no authentication required.

### Likelihood Explanation
The attack requires zero privileges — no account, no API key, no authentication. A single machine with a modest HTTP flood tool (e.g., `wrk`, `ab`, `hey`) can sustain thousands of concurrent connections. The endpoint is publicly documented and trivially discoverable. The attack is repeatable and persistent as long as the flood continues.

### Recommendation
1. Add a per-IP rate-limiting middleware (e.g., `express-rate-limit`) globally in `rest/server.js` before route registration, covering all endpoints.
2. Optionally add a tighter per-route limit specifically for the allowances endpoints via `AccountRoutes.router`.
3. Set a reasonable `maxConnections` pool cap and ensure `connectionTimeoutMillis` is short enough to shed load quickly rather than queue indefinitely.
4. Consider enabling the Redis-backed response cache (`config.cache.response.enabled`) to absorb repeated identical queries without hitting the DB.

### Proof of Concept
```bash
# Flood the endpoint with 500 concurrent connections, no credentials needed
wrk -t10 -c500 -d60s \
  "http://<mirror-node-host>/api/v1/accounts/0.0.1234/allowances/tokens"

# Simultaneously verify that unrelated endpoints also start failing:
curl -v "http://<mirror-node-host>/api/v1/transactions"
# Expected: connection timeout / 503 once pool is exhausted
```

Preconditions: network access to the REST API port. No account or credentials required.
Trigger: sustained concurrent GET requests to `/api/v1/accounts/:id/allowances/tokens`.
Result: PostgreSQL connection pool exhausted → all REST API endpoints return errors for legitimate users.

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

**File:** rest/middleware/authHandler.js (L15-20)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }
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
