### Title
Unauthenticated Double DB Connection Exhaustion via `Promise.all` in `getOneAccount()` with No Rate Limiting

### Summary
`getOneAccount()` in `rest/accounts.js` unconditionally fires two parallel database queries per request via `Promise.all([entityPromise, transactionsPromise])`, consuming two connections from a shared pool (default max: 10). The REST API's Traefik ingress middleware has no `inFlightReq` or `rateLimit` controls (unlike other services such as Rosetta), and there is no application-level rate limiter. An unprivileged attacker can exhaust the entire connection pool with as few as 5 concurrent requests, starving all other REST API endpoints of database connections.

### Finding Description

**Exact code location:** `rest/accounts.js`, function `getOneAccount()`, lines 487–495.

```js
// rest/accounts.js lines 487-495
const entityPromise = pool.queryQuietly(entityQuery, entityParams);          // consumes 1 connection

const transactionsPromise = includeTransactions
  ? transactions.doGetTransactions(filters, req, timestampRange)             // consumes 1+ connections
  : emptyTransactionsPromise;

const [entityResults, transactionResults] = await Promise.all([entityPromise, transactionsPromise]);
``` [1](#0-0) 

Both promises are created and submitted to the pool **before** either awaits, so both connections are checked out simultaneously. `includeTransactions` defaults to `true` (only overridden by an explicit `transactions=false` query param), so the double-connection path is the default for every unauthenticated caller.

**DB pool size:** The default `maxConnections` is 10. [2](#0-1) 

**No application-level rate limiting:** The Express middleware stack is: `httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler → routes → responseHandler → responseCacheUpdateHandler → handleError`. There is no rate-limit or concurrency-limit middleware. [3](#0-2) 

**No infrastructure-level rate limiting for REST:** The REST API's Traefik middleware block contains only `circuitBreaker` and `retry` — no `inFlightReq` and no `rateLimit`. Compare to the Rosetta service, which explicitly configures both. [4](#0-3) [5](#0-4) 

**Retry amplification:** The REST Traefik config sets `retry: attempts: 10`, meaning each failed (pool-exhausted) request is retried up to 10 times, further amplifying load. [6](#0-5) 

**Statement timeout is insufficient:** The 20-second `statementTimeout` limits individual query duration but does not limit concurrency or connection acquisition. During a flood, connections queue rather than immediately fail, prolonging the outage window. [7](#0-6) 

### Impact Explanation

With a pool of 10 connections and 2 consumed per `getOneAccount()` request, only 5 concurrent attacker requests are needed to saturate the pool. All other REST endpoints (`/api/v1/transactions`, `/api/v1/balances`, etc.) share the same pool and are immediately starved. New requests queue until `connectionTimeoutMillis` (default 20 s) elapses, then fail with a 500. The gossip transaction data path referenced in the question — returning transaction records to legitimate callers — is directly disrupted. The attack is sustained with a trivial HTTP flood tool at 5 RPS of concurrent open requests.

### Likelihood Explanation

No authentication, API key, or IP-based throttle is required. Any internet-accessible deployment is reachable. The attack is reproducible with standard tools (`ab`, `wrk`, `curl` in parallel). The attacker does not need to know any valid account ID — any syntactically valid ID (e.g., `0.0.1`) suffices; the entity query will simply return 0 rows after consuming the connection. The `retry: attempts: 10` Traefik setting means each attacker connection attempt is automatically retried, multiplying effective load by up to 10×.

### Recommendation

1. **Add `inFlightReq` per-IP to the REST Traefik middleware** (matching the Rosetta pattern: `amount: 5, sourceCriterion: ipStrategy: depth: 1`).
2. **Add `rateLimit`** to the REST Traefik middleware to cap requests per source.
3. **Reduce default `maxConnections`** or introduce a per-endpoint connection semaphore so `getOneAccount()` cannot monopolize the pool.
4. **Honour `transactions=false` by default** or make the parallel query opt-in, so the single-connection path is the default.
5. **Remove or reduce the `retry: attempts: 10`** for the REST ingress, as retries on a saturated pool amplify rather than recover from the condition.

### Proof of Concept

```bash
# Exhaust the 10-connection pool with 5 concurrent long-running requests
# (timestamp range maximises query duration up to the 20 s statement timeout)
for i in $(seq 1 5); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1?timestamp=gte:0.000000000&timestamp=lte:9999999999.000000000" &
done
wait

# While the above are in-flight, all other REST API calls will queue/fail:
curl -v "https://<mirror-node>/api/v1/transactions"
# Expected: connection timeout or 500 after ~20 s
```

### Citations

**File:** rest/accounts.js (L487-495)
```javascript
  const entityPromise = pool.queryQuietly(entityQuery, entityParams);

  // Add the account id path parameter as a query filter for the transactions handler
  filters.push({key: filterKeys.ACCOUNT_ID, operator: opsMap.eq, value: encodedId});
  const transactionsPromise = includeTransactions
    ? transactions.doGetTransactions(filters, req, timestampRange)
    : emptyTransactionsPromise;

  const [entityResults, transactionResults] = await Promise.all([entityPromise, transactionsPromise]);
```

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
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

**File:** charts/hedera-mirror-rest/values.yaml (L134-139)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
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
