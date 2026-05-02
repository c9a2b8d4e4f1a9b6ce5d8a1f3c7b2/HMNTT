### Title
Unbounded Unauthenticated Pagination Enumeration of Crypto Allowances via `links.next` — No Rate Limiting on REST API

### Summary
The `getAccountCryptoAllowances()` handler in `rest/controllers/cryptoAllowanceController.js` generates a `response.links.next` cursor whenever a full page of results is returned, allowing any unauthenticated caller to traverse the complete set of crypto allowances for any target account. Neither the application middleware stack nor the default Helm chart Traefik middleware for the REST service applies any rate limit or in-flight request cap, making unlimited bulk enumeration of all spender relationships trivially repeatable.

### Finding Description

**Code path — pagination generation:**

In `getAccountCryptoAllowances()`, lines 89–95, when the returned allowance count equals `limit`, a `links.next` URL is unconditionally emitted:

```js
if (response.allowances.length === limit) {
  const lastRow = last(response.allowances);
  const lastValues = {
    [filterKeys.SPENDER_ID]: lastRow.spender,
  };
  response.links.next = utils.getPaginationLink(req, false, lastValues, order);
}
``` [1](#0-0) 

The cursor encodes only the last `spender` ID; there is no session token, HMAC, or expiry baked into the link. Any caller who receives a page can follow `links.next` indefinitely.

**No application-level rate limiting:**

A `grep` across all `rest/**/*.js` for `rateLimit`, `rateLimiter`, or `throttle` returns zero matches in production code. The middleware chain registered in `server.js` is:

```
authHandler → requestLogger → (optional metrics) → (optional cache) →
responseHandler → handleError
``` [2](#0-1) 

There is no rate-limiting middleware anywhere in this chain.

**`authHandler` does not protect unauthenticated callers:**

`authHandler` only activates when HTTP Basic credentials are supplied. If no `Authorization` header is present, the handler returns immediately (`return;`) and the request proceeds with no limit applied:

```js
if (!credentials) {
  return;
}
``` [3](#0-2) 

**No infrastructure-level rate limiting in the REST Helm chart:**

The `hedera-mirror-rest` chart's `middleware` block contains only `circuitBreaker` and `retry`:

```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ...
  - retry:
      attempts: 10
      initialInterval: 100ms
``` [4](#0-3) 

Compare this with the `hedera-mirror-rosetta` chart, which explicitly adds `inFlightReq` (5 concurrent requests per IP) and `rateLimit` (10 req/s per host). The REST chart has neither. Furthermore, `global.middleware: false` means the Traefik middleware chain is disabled by default even for the circuit breaker. [5](#0-4) 

### Impact Explanation

An attacker can issue repeated GET requests to `/api/v1/accounts/{id}/allowances/crypto`, following each `links.next` cursor, to reconstruct the complete set of `(owner, spender, amount)` tuples for any target account. Aggregated across many accounts, this yields a full graph of crypto-allowance relationships — effectively a map of which accounts have delegated spending authority to which others. This graph directly reflects the economic and operational relationships between accounts and can be used to infer transaction routing, identify high-value custodians, and target social-engineering or phishing campaigns against known spenders. Because the data is served without authentication or throttling, the enumeration is free, fast, and leaves no distinguishing fingerprint beyond normal HTTP access logs.

### Likelihood Explanation

Preconditions are zero: no account, no API key, no special network position is required. The attacker needs only an HTTP client. The `limit` parameter defaults to 25 and is capped at 100 per page, so even large allowance sets are fully traversable in tens of requests. The attack is fully automatable, repeatable at will, and indistinguishable from legitimate API usage. Public mirror node deployments (e.g., `mainnet-public.mirrornode.hedera.com`) expose this endpoint directly to the internet.

### Recommendation

1. **Add a Traefik `rateLimit` and `inFlightReq` middleware to the REST chart**, mirroring the rosetta chart configuration:
   ```yaml
   - inFlightReq:
       amount: 10
       sourceCriterion:
         ipStrategy:
           depth: 1
   - rateLimit:
       average: 50
       burst: 20
       sourceCriterion:
         ipStrategy:
           depth: 1
   ```
   and set `global.middleware: true` by default.

2. **Add application-level throttling** in `server.js` using a library such as `express-rate-limit`, applied globally before route handlers, so that deployments without Traefik are also protected.

3. **Enforce a hard maximum on the `limit` query parameter** (already capped at 100 by `getResponseLimit`) and consider adding a per-IP request counter in the `authHandler` path for unauthenticated callers.

### Proof of Concept

```bash
# Step 1: fetch first page (no credentials required)
curl -s "https://<mirror-node>/api/v1/accounts/0.0.12345/allowances/crypto?limit=100&order=asc" \
  | tee page1.json | jq '.links.next'

# Step 2: follow the next link — repeat until links.next is null
NEXT=$(jq -r '.links.next' page1.json)
while [ "$NEXT" != "null" ]; do
  curl -s "https://<mirror-node>${NEXT}" | tee pageN.json
  NEXT=$(jq -r '.links.next' pageN.json)
done

# Result: complete list of all (spender, amount, amountGranted) tuples
# for account 0.0.12345, obtained with zero authentication and zero rate limiting.
```

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L89-95)
```javascript
    if (response.allowances.length === limit) {
      const lastRow = last(response.allowances);
      const lastValues = {
        [filterKeys.SPENDER_ID]: lastRow.spender,
      };
      response.links.next = utils.getPaginationLink(req, false, lastValues, order);
    }
```

**File:** rest/server.js (L83-144)
```javascript
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

**File:** rest/middleware/authHandler.js (L18-20)
```javascript
  if (!credentials) {
    return;
  }
```

**File:** charts/hedera-mirror-rest/values.yaml (L89-89)
```yaml
  middleware: false
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
