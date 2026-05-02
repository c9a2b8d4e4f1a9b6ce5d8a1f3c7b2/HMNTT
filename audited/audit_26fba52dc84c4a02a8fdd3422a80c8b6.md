### Title
Absence of Rate Limiting on REST API Allows Connection Pool Exhaustion via Concurrent NFT Endpoint Requests

### Summary
The Node.js REST API has no per-user or global rate limiting middleware. The `/api/v1/tokens/:tokenId/nfts/:serialNumber/transactions` endpoint calls `getNftTransferHistoryRequest`, which issues up to three sequential `pool.queryQuietly` calls against the shared global connection pool — including a call to `NftService.getNft()`. An unauthenticated attacker flooding this endpoint with concurrent requests can exhaust the finite pool, causing connection timeouts and 503 errors for all other API consumers.

### Finding Description
**Code path:**

`rest/service/nftService.js`, `getNft()`, lines 38–41:
```js
async getNft(tokenId, serialNumber) {
  const {rows} = await pool.queryQuietly(NftService.nftByIdQuery, [tokenId, serialNumber]);
  return isEmpty(rows) ? null : new Nft(rows[0]);
}
``` [1](#0-0) 

`getNft()` is invoked from `getNftTransferHistoryRequest` in `rest/tokens.js` at line 1047, but only after two prior sequential `pool.queryQuietly` calls at lines 1022 and 1032: [2](#0-1) 

This means each request to `GET /api/v1/tokens/:tokenId/nfts/:serialNumber/transactions` can issue **up to three sequential database queries** against the shared global pool.

**Pool initialization** (`rest/dbpool.js`, lines 7–16) creates a single global `pool` with a finite `max: config.db.pool.maxConnections`: [3](#0-2) 

**No rate limiting exists** in the REST API middleware stack. `rest/server.js` registers: `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler` — no throttle or rate-limit middleware: [4](#0-3) 

The `authHandler` middleware handles per-user response limits, not request rate limiting. The throttling found in `web3/src/main/java/.../ThrottleConfiguration.java` applies only to the Java web3 module, not this Node.js REST service.

**Root cause:** The REST API trusts that infrastructure-level controls (load balancer, ingress) will absorb floods. There is no application-layer guard. The `connectionTimeoutMillis` and `statement_timeout` pool settings only bound individual query duration; they do not prevent the pool queue from growing unboundedly under concurrent load. [5](#0-4) 

### Impact Explanation
When the pool is saturated, all subsequent `pool.queryQuietly` calls queue until `connectionTimeoutMillis` expires, at which point they throw a `DbError`, which the error handler maps to HTTP 503 (`SERVICE_UNAVAILABLE`): [6](#0-5) 

This affects **all** REST API endpoints sharing the same pool — accounts, transactions, balances, etc. — not just the NFT endpoint. The impact is a full REST API outage for legitimate users for the duration of the attack.

### Likelihood Explanation
No authentication or API key is required to call `GET /api/v1/tokens/:tokenId/nfts/:serialNumber/transactions`. Any unprivileged external user can issue requests. The attack requires only a modest number of concurrent HTTP connections (matching or exceeding `maxConnections`) sustained over time. Standard HTTP benchmarking tools (`wrk`, `ab`, `hey`) are sufficient. The attack is trivially repeatable and requires no special knowledge beyond the public API spec.

### Recommendation
1. **Add a global rate-limiting middleware** to `rest/server.js` (e.g., `express-rate-limit`) applied before route handlers, limiting requests per IP per time window.
2. **Add per-endpoint concurrency limits** or a semaphore for endpoints that issue multiple sequential DB queries.
3. **Set a pool queue limit** (`maxQueue` / `allowExitOnIdle` in node-postgres) so that excess requests fail fast with 429 rather than queuing indefinitely.
4. **Deploy an ingress-level rate limiter** (e.g., nginx `limit_req`, Kubernetes ingress annotations) as a defense-in-depth layer.

### Proof of Concept
```bash
# Flood the NFT transaction history endpoint with concurrent requests
# Replace TOKEN_ID and SERIAL with valid values from the public ledger
wrk -t 50 -c 500 -d 30s \
  "https://<mirror-node-host>/api/v1/tokens/0.0.1234/nfts/1/transactions"

# Simultaneously observe that other endpoints return 503
curl "https://<mirror-node-host>/api/v1/accounts/0.0.2"
# Expected: {"_status":{"messages":[{"message":"Service Unavailable"}]}}
```

During the flood, pool connections are held by the three sequential queries per request in `getNftTransferHistoryRequest`. Once `maxConnections` is reached, all new requests across the entire API queue and eventually time out, producing 503 responses for all users.

### Citations

**File:** rest/service/nftService.js (L38-41)
```javascript
  async getNft(tokenId, serialNumber) {
    const {rows} = await pool.queryQuietly(NftService.nftByIdQuery, [tokenId, serialNumber]);
    return isEmpty(rows) ? null : new Nft(rows[0]);
  }
```

**File:** rest/tokens.js (L1022-1047)
```javascript
  const {rows} = await pool.queryQuietly(timestampQuery, timestampParams);
  if (rows.length === 0) {
    return;
  }

  // Get nft transfer related transaction details
  const jsonbPathQueryVars = utils.JSONStringify({token_id: tokenId, serial_number: serialNumber});
  const timestamps = rows.map((r) => r.timestamp);
  const query = `${nftTransactionHistoryDetailsQuery} ${order}`;
  const params = [tokenId, serialNumber, jsonbPathQueryVars, timestamps];
  const {rows: transactions} = await pool.queryQuietly(query, params);

  response.transactions = transactions.map(formatNftTransactionHistoryRow);
  const anchorTimestamp = last(response.transactions)?.consensus_timestamp ?? 0;
  response.links.next = utils.getPaginationLink(
    req,
    response.transactions.length !== limit,
    {
      [filterKeys.TIMESTAMP]: anchorTimestamp,
    },
    order
  );

  if (response.transactions.length > 0) {
    // check if nft exists
    const nft = await NftService.getNft(tokenId, serialNumber);
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

**File:** rest/middleware/httpErrorHandler.js (L21-22)
```javascript
  } else if (err instanceof DbError) {
    statusCode = httpStatusCodes.SERVICE_UNAVAILABLE;
```
