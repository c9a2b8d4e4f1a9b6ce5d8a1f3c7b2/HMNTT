### Title
Unbounded Database Query Amplification via Uncached `isValidAccount()` with No Rate Limiting on Public REST Endpoints

### Summary
The `isValidAccount()` function in `rest/service/entityService.js` executes a raw database query on every invocation with no result caching. Two public REST endpoints — `/accounts/:id/tokens` and `/accounts/:id/rewards` — call this function unconditionally before serving any response. Because the REST server has no rate-limiting middleware, an unprivileged attacker can flood these endpoints with unique accountId values to saturate the database connection pool and degrade service for all users.

### Finding Description

**Exact code path:**

`isValidAccount()` at [1](#0-0)  calls `super.getSingleRow(EntityService.entityExistenceQuery, [accountId])`, which is defined at [2](#0-1)  as a bare `SELECT type FROM entity WHERE id = $1` with no caching.

`getSingleRow` in `BaseService` at [3](#0-2)  directly calls `this.pool().queryQuietly(query, params)` — no memoization, no Redis lookup, no in-process cache.

This is triggered unconditionally in two public controller handlers:

- `tokenController.getTokenRelationships` at [4](#0-3)  — serves `GET /api/v1/accounts/:id/tokens`
- `accountController.listStakingRewardsByAccountId` at [5](#0-4)  — serves `GET /api/v1/accounts/:id/rewards`

**Root cause — failed assumption:** The design assumes either (a) callers are rate-limited at the infrastructure layer, or (b) the optional Redis response cache absorbs repeated requests. Neither assumption holds reliably.

**Why existing checks are insufficient:**

The REST server middleware stack at [6](#0-5)  contains: URL encoding, JSON parsing, CORS, compression, HTTP context, request logging, `authHandler`, optional metrics, and optional response cache. There is **no rate-limiting middleware** anywhere in the chain.

The response cache at [7](#0-6)  is gated on both `config.cache.response.enabled` AND `config.redis.enabled` being true simultaneously — it is off by default and absent in many deployments. Even when enabled, it caches full HTTP responses keyed by URL; an attacker using unique or sequential accountIds produces a distinct cache key per request, bypassing the cache entirely and still hitting `isValidAccount()` → DB for every request.

The rate-limiting code that does exist (`ThrottleManagerImpl`, `RequestProperties`) is in the separate `web3` Java service at [8](#0-7)  and has no effect on the Node.js REST service.

### Impact Explanation
Each HTTP request to either affected endpoint causes at minimum one synchronous database round-trip for the existence check, plus additional queries if the account is found. A sustained flood of requests with rotating accountIds exhausts the PostgreSQL connection pool, causing query queuing and timeouts that degrade or deny service to all legitimate users of the mirror node REST API. Because the mirror node is critical read infrastructure for the Hedera network (wallets, explorers, dApps), availability loss has broad downstream impact.

### Likelihood Explanation
The attack requires zero authentication, zero privileges, and no special knowledge — only the ability to send HTTP GET requests to a public endpoint. The attacker needs no valid accountIds; non-existent IDs still trigger the full DB query path (the query returns zero rows, `getSingleRow` returns `null`, `isValidAccount` returns `false`). The attack is trivially scriptable with any HTTP load tool (`curl`, `wrk`, `ab`) and is fully repeatable. Sequential integer IDs (0.0.1, 0.0.2, …) or random large integers both work equally well.

### Recommendation
1. **Add rate limiting to the REST service** — integrate a middleware such as `express-rate-limit` (per-IP) in `rest/server.js` before route handlers, or enforce limits at the reverse-proxy/ingress layer (e.g., Traefik `rateLimit` middleware, already partially scaffolded in `charts/hedera-mirror-web3/templates/middleware.yaml`).
2. **Cache `isValidAccount` results** — introduce a short-lived (e.g., 30-second) in-process LRU cache keyed on `accountId` inside `EntityService.isValidAccount()`, independent of the Redis response cache, so repeated checks for the same ID do not hit the database.
3. **Enforce a DB connection pool cap with fast-fail** — configure `pg` pool `max` and `connectionTimeoutMillis` so that pool exhaustion returns a 503 quickly rather than queuing indefinitely.

### Proof of Concept
```bash
# Flood /accounts/:id/tokens with unique sequential IDs (no auth required)
# Each request triggers isValidAccount() -> SELECT type FROM entity WHERE id = $1

BASE_URL="https://<mirror-node-host>/api/v1"

for i in $(seq 1 100000); do
  curl -s -o /dev/null "${BASE_URL}/accounts/0.0.${i}/tokens" &
  # or: "${BASE_URL}/accounts/0.0.${i}/rewards"
done
wait

# Observe: database connection pool exhaustion, rising query latency,
# 503/timeout responses for legitimate users.
```

Reproducible steps:
1. Stand up the mirror node REST service with Redis disabled (default) or with Redis enabled but use unique accountIds per request.
2. Run the loop above from a single machine (or distribute across a few IPs to avoid any upstream TCP connection limits).
3. Monitor PostgreSQL `pg_stat_activity` — connection slots fill; `SELECT type FROM entity WHERE id = $1` queries queue.
4. Legitimate API calls begin timing out or receiving 503 errors.

### Citations

**File:** rest/service/entityService.js (L28-30)
```javascript
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/service/baseService.js (L59-66)
```javascript
  async getSingleRow(query, params) {
    const rows = await this.getRows(query, params);
    if (isEmpty(rows) || rows.length > 1) {
      return null;
    }

    return rows[0];
  }
```

**File:** rest/controllers/tokenController.js (L66-71)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/controllers/accountController.js (L170-175)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L20-49)
```java
final class ThrottleManagerImpl implements ThrottleManager {

    static final String REQUEST_PER_SECOND_LIMIT_EXCEEDED = "Requests per second rate limit exceeded";
    static final String GAS_PER_SECOND_LIMIT_EXCEEDED = "Gas per second rate limit exceeded.";

    @Qualifier(GAS_LIMIT_BUCKET)
    private final Bucket gasLimitBucket;

    @Qualifier(RATE_LIMIT_BUCKET)
    private final Bucket rateLimitBucket;

    @Qualifier(OPCODE_RATE_LIMIT_BUCKET)
    private final Bucket opcodeRateLimitBucket;

    private final ThrottleProperties throttleProperties;

    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
