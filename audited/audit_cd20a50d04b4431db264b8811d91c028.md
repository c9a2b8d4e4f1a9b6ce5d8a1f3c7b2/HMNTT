### Title
Connection Pool Exhaustion DoS via Unbounded Concurrent Requests in REST API

### Summary
The `parseDbPoolConfig()` function in `rest/config.js` validates only that pool parameters are positive integers, imposing no upper ceiling on `maxConnections` and no lower bound that accounts for realistic concurrency. Combined with the absence of any application-level or infrastructure-level rate limiting or per-IP in-flight request controls for the Node.js REST API, an unprivileged attacker can exhaust all 10 default database connections with concurrent requests, causing every subsequent request to queue and block for up to `connectionTimeoutMillis` (20,000 ms) before returning an error, effectively denying service to all legitimate users.

### Finding Description

**Code path:**

`parseDbPoolConfig()` at [1](#0-0)  validates each of `connectionTimeout`, `maxConnections`, and `statementTimeout` only with `Number.isNaN(parsed) || parsed <= 0`. There is no maximum ceiling check on `maxConnections`. The default value of 10 is accepted without any validation that it is sufficient relative to expected concurrency.

`rest/dbpool.js` directly maps this to the `pg` Pool: [2](#0-1)  — `max: config.db.pool.maxConnections` (default 10) and `connectionTimeoutMillis: config.db.pool.connectionTimeout` (default 20000 ms). When all 10 connections are occupied, `pg.Pool` queues new acquire requests and waits up to 20 seconds before throwing a timeout error.

**No application-level rate limiting exists.** The `server.js` middleware stack is: [3](#0-2)  — `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`, route handlers, `responseHandler`, `handleError`. There is no rate-limiting or in-flight concurrency middleware anywhere in this chain.

**Infrastructure-level protection is disabled by default.** The Helm chart for the REST API defines: [4](#0-3)  — `global.middleware: false` (line 89), meaning the Traefik middleware chain is not applied by default. Even when enabled, the REST API's middleware list contains only `circuitBreaker` and `retry` — critically missing `inFlightReq` and `rateLimit` that are present in the Rosetta API chart. Compare with Rosetta: [5](#0-4)  which includes `inFlightReq: amount: 5` per IP and `rateLimit: average: 10`.

**Root cause:** `parseDbPoolConfig()` accepts any positive integer for `maxConnections` with no upper ceiling and no relationship to expected concurrency. The default of 10 is trivially exhaustible. No compensating control exists at the application layer or (by default) at the infrastructure layer.

### Impact Explanation

When all 10 pool connections are held by attacker-controlled requests, every legitimate API request blocks in the `pg.Pool` queue for up to 20 seconds before receiving a connection timeout error. During this window, the REST API is functionally unavailable to all users — all endpoints (`/api/v1/transactions`, `/api/v1/accounts`, etc.) share the same pool. The `statement_timeout` of 20,000 ms means attacker connections are eventually released, but the attacker only needs to continuously resend requests to maintain saturation. The `circuitBreaker` middleware (when enabled) triggers on `NetworkErrorRatio() > 0.25`, which would eventually trip — but the `retry: attempts: 10` middleware would then amplify load by retrying each failed request up to 10 times, worsening the condition.

**Severity: High** — complete denial of service of the public REST API achievable with minimal resources.

### Likelihood Explanation

No authentication is required. Any HTTP client capable of sending concurrent requests (e.g., `ab`, `wrk`, `curl` with `&`) can trigger this. The attacker needs only to send 10+ concurrent requests to any DB-backed endpoint and sustain them. Queries with larger result sets (e.g., `GET /api/v1/transactions?limit=25`) naturally hold connections longer. This is repeatable, requires no special knowledge of the system, and is a standard HTTP flood pattern. The default deployment (`global.middleware: false`) provides zero infrastructure-level protection.

### Recommendation

1. **Add an upper ceiling in `parseDbPoolConfig()`**: Validate that `maxConnections` does not exceed a reasonable maximum (e.g., 100) and emit a warning if it is below a minimum safe threshold.
2. **Add `inFlightReq` and `rateLimit` to the REST API Traefik middleware** in `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta chart's configuration.
3. **Enable `global.middleware: true` by default** or document clearly that production deployments require it.
4. **Add application-level concurrency limiting** (e.g., `express-rate-limit` or a semaphore on DB pool acquisition) so the Node.js process itself rejects excess requests with HTTP 429 before they queue in the pool.
5. **Increase `maxConnections` default** or use a connection pooler (e.g., PgBouncer) in front of PostgreSQL.

### Proof of Concept

**Preconditions:** Default deployment with `global.middleware: false` (the default), `maxConnections: 10`, `connectionTimeoutMillis: 20000`.

**Steps:**

```bash
# Step 1: Send 15 concurrent slow requests to exhaust the pool
# (transactions endpoint performs a DB query on every request)
for i in $(seq 1 15); do
  curl -s "http://<REST_API_HOST>/api/v1/transactions?limit=25" &
done

# Step 2: Immediately send a legitimate request and observe the delay
time curl -s "http://<REST_API_HOST>/api/v1/transactions?limit=1"
```

**Expected result:** The legitimate request in Step 2 blocks for ~20 seconds (connectionTimeoutMillis) and then returns a 500 error with a connection timeout message, or hangs until a connection is released. Repeating Step 1 continuously maintains the DoS condition indefinitely with no authentication required.

### Citations

**File:** rest/config.js (L137-148)
```javascript
function parseDbPoolConfig() {
  const {pool} = getConfig().db;
  const configKeys = ['connectionTimeout', 'maxConnections', 'statementTimeout'];
  configKeys.forEach((configKey) => {
    const value = pool[configKey];
    const parsed = parseInt(value, 10);
    if (Number.isNaN(parsed) || parsed <= 0) {
      throw new InvalidConfigError(`invalid value set for db.pool.${configKey}: ${value}`);
    }
    pool[configKey] = parsed;
  });
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

**File:** rest/server.js (L68-144)
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

// balances routes
app.getExt(`${apiPrefix}/balances`, balances.getBalances);

// contracts routes
app.use(`${apiPrefix}/${ContractRoutes.resource}`, ContractRoutes.router);

// block routes
app.use(`${apiPrefix}/${BlockRoutes.resource}`, BlockRoutes.router);

// schedules routes
app.getExt(`${apiPrefix}/schedules`, schedules.getSchedules);
app.getExt(`${apiPrefix}/schedules/:scheduleId`, schedules.getScheduleById);

// tokens routes
app.getExt(`${apiPrefix}/tokens`, tokens.getTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId`, tokens.getTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/balances`, tokens.getTokenBalances);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts`, tokens.getNftTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber`, tokens.getNftTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber/transactions`, tokens.getNftTransferHistoryRequest);

// topics routes
app.getExt(`${apiPrefix}/topics/:topicId/messages`, topicmessage.getTopicMessages);
app.getExt(`${apiPrefix}/topics/:topicId/messages/:sequenceNumber`, topicmessage.getMessageByTopicAndSequenceRequest);
app.getExt(`${apiPrefix}/topics/messages/:consensusTimestamp`, topicmessage.getMessageByConsensusTimestamp);

// transactions routes
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
app.getExt(`${apiPrefix}/transactions/:transactionIdOrHash`, transactions.getTransactionsByIdOrHash);

// response data handling middleware
app.useExt(responseHandler);

// Update Cache with response
if (applicationCacheEnabled) {
  app.useExt(responseCacheUpdateHandler);
}

// response error handling middleware
app.useExt(handleError);
```

**File:** charts/hedera-mirror-rest/values.yaml (L82-139)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
  podAnnotations: {}

hpa:
  behavior: {}
  enabled: true
  maxReplicas: 15
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80

  minReplicas: 1

image:
  pullPolicy: IfNotPresent
  pullSecrets: []
  registry: gcr.io
  repository: mirrornode/hedera-mirror-rest
  tag: ""  # Defaults to the chart's app version

ingress:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: '{{ include "hedera-mirror-rest.namespace" . }}-{{ include "hedera-mirror-rest.fullname" . }}@kubernetescrd'
  enabled: true
  hosts:
    - host: ""
      paths: ["/api/v1"]
  tls:
    enabled: false
    secretName: ""

labels: {}

livenessProbe:
  httpGet:
    path: /health/liveness
    port: http
  initialDelaySeconds: 0
  timeoutSeconds: 2

middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
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
  - stripPrefix:
      prefixes:
        - "/rosetta"
```
