### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded Concurrent Requests to `/accounts/{id}/tokens`

### Summary
The `getTokenRelationships()` handler in `rest/controllers/tokenController.js` performs a synchronous database query against the `token_account` table on every request with no rate limiting applied at any layer of the REST API. The default DB connection pool is capped at 10 connections with a 20-second statement timeout, meaning an attacker sending as few as 10 concurrent requests can hold all pool connections simultaneously, causing connection timeout errors for all other users of the REST API.

### Finding Description
**Exact code path:**

`rest/controllers/tokenController.js`, `getTokenRelationships()` (lines 66–92) calls `EntityService.getEncodedId()` (a DB lookup), then `EntityService.isValidAccount()` (another DB lookup), then `TokenService.getTokenAccounts()` (lines 74, 96–115 in `rest/service/tokenService.js`) which executes a parameterized query against `token_account` filtered by `account_id` and optionally a `token_id` range condition.

**Root cause:**

The REST API server (`rest/server.js`) registers no rate-limiting middleware. The full middleware stack is: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — none of which throttle request rate or concurrency per IP or globally. The throttle mechanism (`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`) exists only in the `web3` Java module and is entirely absent from the Node.js REST API.

**DB pool configuration:**

`rest/dbpool.js` (lines 7–16) configures the pool with `max: config.db.pool.maxConnections` and `statement_timeout: config.db.pool.statementTimeout`. Per `docs/configuration.md` (lines 556–557), the defaults are `maxConnections = 10` and `statementTimeout = 20000` ms. Each request to `getTokenRelationships()` acquires a pool connection for the duration of the query (up to 20 seconds). With `connectionTimeout = 20000` ms (line 555), requests queued beyond the 10-connection limit will block for 20 seconds before failing.

**Why existing checks fail:**

- `authHandler.js` (lines 15–36) only sets a custom response `limit` for authenticated users; it does not throttle or reject unauthenticated requests.
- `maxRepeatedQueryParameters = 100` (docs line 581) limits parameter repetition but does not limit request rate.
- The `token.id` range filter (`gt`, `lt`, `gte`, `lte`) is accepted without restriction, and each unique range value bypasses any response cache (cache key includes query params), guaranteeing a fresh DB query per request.

### Impact Explanation
An attacker sending 10+ concurrent requests with varying `token.id` range values exhausts the 10-connection pool. All subsequent REST API requests — across all endpoints, not just `/accounts/{id}/tokens` — queue for up to 20 seconds before receiving a connection timeout error. This constitutes a full REST API denial of service affecting all users. The attack is amplified by the two sequential DB calls per request (`getEncodedId` + `isValidAccount` before the main query), meaning each request may hold a connection for multiple sequential operations.

### Likelihood Explanation
No authentication, API key, or network-level credential is required. Any internet-accessible deployment is vulnerable. The attack requires only a valid account ID (trivially obtained from any public Hedera explorer) and a simple HTTP flood tool (e.g., `ab`, `wrk`, or a short script). The attacker needs to sustain only 10 concurrent in-flight requests — a trivial load — to maintain pool exhaustion indefinitely. The attack is repeatable and requires no special knowledge beyond the public API spec.

### Recommendation
1. Add a global rate-limiting middleware to the REST API Express app (e.g., `express-rate-limit`) applied before route handlers, limiting requests per IP per second.
2. Increase `maxConnections` and/or reduce `statementTimeout` to limit per-query hold time.
3. Add a concurrency limiter (e.g., `p-limit` or a semaphore) around DB pool acquisition in `BaseService.getRows()` to cap simultaneous in-flight queries.
4. Consider deploying an API gateway or reverse proxy (e.g., nginx, Envoy) with connection rate limiting in front of the REST service.

### Proof of Concept
```bash
# Requires: a valid account ID (e.g., 0.0.98 exists on all networks)
# Send 20 concurrent requests with varying token.id ranges, holding connections

for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>:5551/api/v1/accounts/0.0.98/tokens?token.id=gt:0.0.$((i*1000))&limit=100" &
done
wait

# Simultaneously, observe that legitimate requests to any REST endpoint
# (e.g., /api/v1/transactions) time out or return connection errors
curl -v "http://<mirror-node-host>:5551/api/v1/transactions"
# Expected: hangs for ~20s then fails with connection pool exhaustion error
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/controllers/tokenController.js (L66-74)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenParameters);
    const query = this.extractTokensRelationshipQuery(filters, accountId);
    const tokenRelationships = await TokenService.getTokenAccounts(query);
```

**File:** rest/service/tokenService.js (L96-98)
```javascript
  async getTokenAccounts(query) {
    const {sqlQuery, params} = this.getTokenRelationshipsQuery(query);
    const rows = await super.getRows(sqlQuery, params);
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
