### Title
Unauthenticated DB Connection Pool Exhaustion via `/api/v1/contracts/results/:transactionIdOrHash` Enabling Mirror Node REST API DoS

### Summary
The REST API endpoint `GET /api/v1/contracts/results/:transactionIdOrHash` has no per-IP or per-user rate limiting, while the default DB connection pool is capped at 10 connections with a 20-second statement timeout. An unprivileged attacker can hold all 10 connections simultaneously by sending concurrent requests, starving legitimate queries. The Traefik middleware for the REST service omits both `inFlightReq` and `rateLimit` controls that are present on other mirror node services (Rosetta, GraphQL), making this gap a concrete, exploitable asymmetry.

### Finding Description

**Code path:**

`getContractResultsByTransactionIdOrHash` in `rest/controllers/contractController.js` (lines 1120–1202) handles the endpoint. When the path parameter is a transaction ID (not an ETH hash), it calls:

```js
const transactions = await TransactionService.getTransactionDetailsFromTransactionId(transactionId, nonce);
```

`getTransactionDetailsFromTransactionId` in `rest/service/transactionService.js` (lines 64–72) executes a parameterized SQL query against the `transaction` table, acquiring a connection from the shared pool for up to `statementTimeout` milliseconds.

The pool is configured in `rest/dbpool.js` (line 14):
```js
max: config.db.pool.maxConnections,  // default: 10
```
with `connectionTimeoutMillis: 20000` and `statement_timeout: 20000` (both 20 s), as documented in `docs/configuration.md` lines 555–557.

**Missing controls:**

`rest/server.js` (lines 68–144) registers no rate-limiting middleware. The full middleware stack is: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler` (response-limit only), optional `metricsHandler`, optional `responseCacheCheckHandler`, routes, `responseHandler`, `handleError`. No `express-rate-limit`, no token bucket, no concurrency cap.

At the infrastructure layer, `charts/hedera-mirror-rest/values.yaml` lines 134–139 show the Traefik middleware for the REST service:
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```
No `inFlightReq`, no `rateLimit`. Compare with `charts/hedera-mirror-rosetta/values.yaml` lines 149–163, which includes both `inFlightReq` (5 per IP) and `rateLimit` (10/s per host), and `charts/hedera-mirror-graphql/values.yaml` lines 135–145, which includes `inFlightReq`. The REST service is the only one missing both.

The `retry: attempts: 10` middleware actively amplifies the attack: each attacker request that times out is retried up to 10 times by Traefik, multiplying connection pressure by up to 10×.

**Root cause:** The REST API assumes upstream infrastructure will enforce concurrency/rate limits, but the deployed Traefik middleware for this service omits those controls entirely.

### Impact Explanation

With 10 connections and a 20 s timeout, an attacker needs only 10 concurrent long-running requests to saturate the pool. All other REST API endpoints share the same pool (`global.pool` in `rest/dbpool.js`), so pool exhaustion blocks every endpoint — `/api/v1/transactions/:id`, `/api/v1/accounts`, etc. — not just the contract results endpoint. Clients and dApps relying on the mirror node to verify transaction finality receive connection-timeout errors for the full duration of the attack. The HPA (`maxReplicas: 15`) can scale pods, but each pod has its own 10-connection pool and the attacker can trivially scale requests proportionally. The circuit breaker only trips reactively after 25% error rate is sustained, by which point the DoS is already in effect.

### Likelihood Explanation

No authentication, no API key, no CAPTCHA, and no IP-based throttle is required. Any internet-accessible mirror node deployment is reachable. The attack requires only a script sending 10–15 concurrent HTTP GET requests with syntactically valid transaction IDs (e.g., `0.0.1234-1234567890-000000000`). The 20 s statement timeout means the attacker must sustain ~10 req/s to keep the pool saturated continuously. This is trivially achievable from a single machine or a small botnet. The attack is repeatable indefinitely with no cost to the attacker.

### Recommendation

1. **Add `inFlightReq` and `rateLimit` to the REST Traefik middleware** in `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta configuration (e.g., `inFlightReq.amount: 5` per IP, `rateLimit.average: 50` per host).
2. **Add application-level concurrency limiting** in `rest/server.js` using a middleware such as `express-rate-limit` or `bottleneck` scoped per IP, applied before route handlers.
3. **Reduce `maxConnections` exposure** by enabling the Redis response cache (`cache.response.enabled: true`) so repeated identical lookups do not hit the DB.
4. **Reduce `statementTimeout`** for this endpoint's query class, or add a query-level timeout shorter than the pool `connectionTimeout` so connections are released faster under load.
5. **Remove or cap the `retry: attempts: 10`** Traefik middleware for the REST service, as it amplifies rather than mitigates pool exhaustion.

### Proof of Concept

```bash
# Saturate the 10-connection pool with concurrent requests holding connections for ~20s each
# Replace <MIRROR_NODE_HOST> with the target

for i in $(seq 1 15); do
  curl -s "https://<MIRROR_NODE_HOST>/api/v1/contracts/results/0.0.9999-$(date +%s)-000000000" &
done
wait

# Immediately probe a legitimate endpoint — expect connection timeout or 503
curl -v "https://<MIRROR_NODE_HOST>/api/v1/transactions/0.0.1234-1234567890-000000000"
```

Expected result: the legitimate probe hangs until a connection is freed (up to 20 s) or returns a 503/timeout error, demonstrating full pool exhaustion. Sustained at 10–15 req/s, this keeps the pool saturated continuously. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

### Title
Unauthenticated DB Connection Pool Exhaustion via `/api/v1/contracts/results/:transactionIdOrHash` Enabling Mirror Node REST API DoS

### Summary
The REST API endpoint `GET /api/v1/contracts/results/:transactionIdOrHash` has no per-IP or per-user rate limiting at either the application or infrastructure layer. The default DB connection pool is capped at 10 connections with a 20-second statement timeout. An unprivileged attacker can hold all 10 connections simultaneously with concurrent requests, starving every other REST API query. The Traefik middleware for the REST service omits both `inFlightReq` and `rateLimit` controls that are present on other mirror node services (Rosetta, GraphQL), making this a concrete, verifiable gap.

### Finding Description

**Exact code path:**

`getContractResultsByTransactionIdOrHash` in `rest/controllers/contractController.js` (lines 1120–1150) handles the endpoint. When the path parameter is a transaction ID (not an ETH hash), it calls:

```js
const transactions = await TransactionService.getTransactionDetailsFromTransactionId(transactionId, nonce);
```

`getTransactionDetailsFromTransactionId` in `rest/service/transactionService.js` (lines 64–72) executes a parameterized SQL SELECT against the `transaction` table, acquiring a connection from the shared global pool for the duration of the query (up to `statementTimeout` ms).

**Pool configuration** — `rest/dbpool.js` line 14:
```js
max: config.db.pool.maxConnections,  // default: 10
```
`docs/configuration.md` lines 555–557 confirm the defaults:
- `maxConnections`: **10**
- `connectionTimeout`: **20000 ms**
- `statementTimeout`: **20000 ms**

**No application-level rate limiting** — `rest/server.js` lines 68–144 register the full middleware stack: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler` (response-limit only, not rate-limiting), optional `metricsHandler`, optional `responseCacheCheckHandler`, routes, `responseHandler`, `handleError`. No token bucket, no concurrency cap, no `express-rate-limit`.

**No infrastructure-level rate limiting** — `charts/hedera-mirror-rest/values.yaml` lines 134–139 show the Traefik middleware for the REST service:
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```
No `inFlightReq`, no `rateLimit`.

**Contrast with other services** — `charts/hedera-mirror-rosetta/values.yaml` lines 149–163 includes both `inFlightReq` (5 concurrent per IP) and `rateLimit` (10/s per host). `charts/hedera-mirror-graphql/values.yaml` lines 135–145 includes `inFlightReq` (5 per IP). The REST service is the only one missing both controls.

**The `retry: attempts: 10` middleware actively amplifies the attack**: each attacker request that times out is retried up to 10 times by Traefik, multiplying connection pressure by up to 10×.

**Root cause:** The REST API assumes upstream infrastructure enforces concurrency/rate limits, but the deployed Traefik middleware for this service omits those controls entirely, while the DB pool is shared across all endpoints.

### Impact Explanation

With 10 connections and a 20 s statement timeout, an attacker needs only 10 concurrent long-running requests to saturate the pool. All REST API endpoints share the same `global.pool` (`rest/dbpool.js`), so pool exhaustion blocks every endpoint — `/api/v1/transactions/:id`, `/api/v1/accounts`, `/api/v1/contracts/results/:transactionIdOrHash`, etc. Clients and dApps relying on the mirror node to verify transaction finality receive connection-timeout errors for the full duration of the attack. The HPA (`maxReplicas: 15`) can scale pods, but each pod has its own 10-connection pool and the attacker can trivially scale requests proportionally. The circuit breaker only trips reactively after 25% error rate is sustained, by which point the DoS is already in effect and the retry amplification has worsened it.

### Likelihood Explanation

No authentication, API key, CAPTCHA, or IP-based throttle is required. Any internet-accessible mirror node deployment is reachable. The attack requires only a script sending 10–15 concurrent HTTP GET requests with syntactically valid transaction IDs (e.g., `0.0.1234-1234567890-000000000`). The 20 s statement timeout means the attacker must sustain ~10 req/s to keep the pool saturated continuously — trivially achievable from a single machine. The attack is repeatable indefinitely at zero cost to the attacker.

### Recommendation

1. **Add `inFlightReq` and `rateLimit` to the REST Traefik middleware** in `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta configuration (e.g., `inFlightReq.amount: 5` per IP, `rateLimit.average: 50` per host).
2. **Add application-level rate limiting** in `rest/server.js` using a middleware such as `express-rate-limit` scoped per IP, applied before route handlers.
3. **Enable the Redis response cache** (`cache.response.enabled: true`) so repeated identical lookups do not hit the DB pool.
4. **Reduce `statementTimeout`** for this endpoint's query class to a value well below `connectionTimeout`, so connections are released faster under load.
5. **Cap or remove `retry: attempts: 10`** in the REST Traefik middleware, as it amplifies rather than mitigates pool exhaustion.

### Proof of Concept

```bash
# Saturate the 10-connection pool with 15 concurrent requests
# Each holds a DB connection for up to 20s (statementTimeout)
# Replace <MIRROR_NODE_HOST> with the target

for i in $(seq 1 15); do
  curl -s "https://<MIRROR_NODE_HOST>/api/v1/contracts/results/0.0.9999-$(date +%s)-000000000" &
done
wait

# Immediately probe a legitimate endpoint — expect timeout or 503
curl -v "https://<MIRROR_NODE_HOST>/api/v1/transactions/0.0.1234-1234567890-000000000"
```

Expected result: the legitimate probe hangs for up to 20 s or returns a 503/timeout error, demonstrating full pool exhaustion. Sustained at 10–15 req/s, this keeps the pool saturated continuously with no authentication required.

### Citations

**File:** rest/service/transactionService.js (L64-72)
```javascript
  async getTransactionDetailsFromTransactionId(transactionId, nonce = undefined) {
    const maxConsensusTimestamp = BigInt(transactionId.getValidStartNs()) + maxTransactionConsensusTimestampRangeNs;
    return this.getTransactionDetails(TransactionService.transactionDetailsFromTransactionIdQuery, [
      transactionId.getEntityId().getEncodedId(),
      transactionId.getValidStartNs(),
      maxConsensusTimestamp,
      nonce,
    ]);
  }
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
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

**File:** rest/controllers/contractController.js (L1120-1150)
```javascript
  getContractResultsByTransactionIdOrHash = async (req, res) => {
    if (utils.conflictingPathParam(req, 'transactionIdOrHash', 'logs')) {
      return;
    }

    utils.validateReq(req, acceptedSingleContractResultsParameters);

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);

    let transactionDetails;

    const {transactionIdOrHash} = req.params;
    if (utils.isValidEthHash(transactionIdOrHash)) {
      const detailsByHash = await ContractService.getContractTransactionDetailsByHash(
        utils.parseHexStr(transactionIdOrHash)
      );
      transactionDetails = detailsByHash[0];
    } else {
      const transactionId = TransactionId.fromString(transactionIdOrHash);
      const nonce = getLastNonceParamValue(req.query);
      // Map the transactions id to a consensus timestamp
      const transactions = await TransactionService.getTransactionDetailsFromTransactionId(transactionId, nonce);

      if (transactions.length === 0) {
        throw new NotFoundError();
      }
      transactionDetails = transactions[0];
      // want to look up involved contract parties using the payer account id
      transactionDetails.entityId = transactionDetails.payerAccountId;
    }
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
