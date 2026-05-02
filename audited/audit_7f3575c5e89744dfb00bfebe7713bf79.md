### Title
Unauthenticated Unbounded Request Flood on `getSchedules()` Enables Account Enumeration and Database Resource Exhaustion

### Summary
The `getSchedules()` handler in `rest/schedules.js` accepts an `account.id` filter with no rate limiting at either the application or infrastructure layer. Any unauthenticated caller can issue unlimited parallel requests, each with a different `account.id`, triggering up to three database queries per request and systematically enumerating every creator account's pending scheduled transactions including their encoded `transaction_body` payloads.

### Finding Description

**Exact code path:**

`getSchedules()` is registered at line 115 of `rest/server.js` with no rate-limiting middleware in the chain:

```
app.getExt(`${apiPrefix}/schedules`, schedules.getSchedules);
``` [1](#0-0) 

The middleware stack registered before this route is: `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`. None of these impose per-IP or global request rate limits. [2](#0-1) 

The `authHandler` only sets a custom response-row limit for authenticated users — it does not throttle or reject unauthenticated requests. [3](#0-2) 

A grep across all `rest/**/*.js` for `rateLimit`, `rateLimiter`, or `throttle` returns zero production matches. The middleware index exports confirm no rate-limiting module exists: [4](#0-3) 

**Database amplification per request:**

Each call to `getSchedules()` with a non-empty result set fires **three** database queries — one for schedules, then two in parallel for entities and signatures: [5](#0-4) 

**`account.id` filter maps directly to `creator_account_id`:** [6](#0-5) 

**Infrastructure-level rate limiting is absent for the REST service:**

The Helm chart `charts/hedera-mirror-rest/values.yaml` defines only `circuitBreaker` and `retry` Traefik middlewares — no `rateLimit` and no `inFlightReq`. Compare this to the Rosetta chart, which explicitly configures both: [7](#0-6) 

**Response includes sensitive scheduled transaction data:**

Each response row exposes `transaction_body` (base64-encoded), `creator_account_id`, `payer_account_id`, `schedule_id`, and all collected signatures: [8](#0-7) 

**Root cause:** The REST service was never given a `rateLimit` or `inFlightReq` Traefik middleware (unlike Rosetta), and the Node.js application layer contains no rate-limiting middleware, leaving `getSchedules()` fully open to unbounded concurrent access.

### Impact Explanation

1. **Database resource exhaustion (DoS):** At N concurrent requests/second, the database receives up to 3N queries/second. The circuit breaker only trips at >25% network error ratio or >25% 5xx ratio — well after the database connection pool is saturated. The `retry` middleware (10 attempts) actively amplifies load during degradation.
2. **Full scheduled-transaction enumeration:** By iterating `account.id` values (Hedera account IDs are sequential integers), an attacker builds a complete map of every creator account's pending scheduled transactions, including the encoded `transaction_body` of each, revealing the exact operations (token transfers, fee payments, etc.) that are scheduled but not yet executed.
3. **No data-access control:** There is no concept of "private" scheduled transactions at the mirror node layer; all are returned to any caller.

### Likelihood Explanation

- **Zero preconditions:** No account, API key, or credential is required.
- **Trivially scriptable:** A simple loop over account IDs (e.g., `0.0.1` through `0.0.N`) with `curl` or any HTTP client suffices.
- **Amplification is automatic:** The three-query-per-request pattern means even moderate request rates (hundreds/second) translate to thousands of DB queries/second.
- **No detection before impact:** The circuit breaker only activates after errors accumulate; there is no proactive throttle.

### Recommendation

1. **Add `rateLimit` and `inFlightReq` Traefik middlewares** to `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta chart configuration (e.g., `average: 100` per source IP, `inFlightReq.amount: 10`).
2. **Add application-level rate limiting** (e.g., `express-rate-limit`) in `rest/server.js` before route registration, keyed on `req.ip`, to provide defense-in-depth independent of the ingress layer.
3. **Remove the `retry` middleware** or reduce its attempts for the REST service, as it amplifies load during saturation rather than protecting it.
4. **Consider requiring pagination cursors** (i.e., disallow open-ended `account.id` scans without a `schedule.id` cursor) to limit the enumeration surface per request.

### Proof of Concept

```bash
# Enumerate creator accounts 1 through 10000 in parallel (50 concurrent)
seq 1 10000 | xargs -P50 -I{} \
  curl -s "https://<mirror-node>/api/v1/schedules?account.id=0.0.{}" \
  -o /dev/null -w "%{http_code} account 0.0.{}\n"

# Collect all non-empty responses to build the fee-obligation map
for id in $(seq 1 10000); do
  result=$(curl -s "https://<mirror-node>/api/v1/schedules?account.id=0.0.$id")
  count=$(echo "$result" | jq '.schedules | length')
  if [ "$count" -gt "0" ]; then
    echo "Account 0.0.$id has $count scheduled transactions"
    echo "$result" | jq '.schedules[].transaction_body'
  fi
done
```

Each iteration with results triggers 3 DB queries. At 50 parallel workers this produces ~150 concurrent DB queries with zero authentication and no server-side throttle.

### Citations

**File:** rest/server.js (L82-98)
```javascript
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

**File:** rest/server.js (L114-116)
```javascript
// schedules routes
app.getExt(`${apiPrefix}/schedules`, schedules.getSchedules);
app.getExt(`${apiPrefix}/schedules/:scheduleId`, schedules.getScheduleById);
```

**File:** rest/middleware/authHandler.js (L15-35)
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
```

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```

**File:** rest/schedules.js (L23-26)
```javascript
const filterColumnMap = {
  [constants.filterKeys.ACCOUNT_ID]: sqlQueryColumns.ACCOUNT,
  [constants.filterKeys.SCHEDULE_ID]: sqlQueryColumns.SCHEDULE_ID,
};
```

**File:** rest/schedules.js (L93-107)
```javascript
  return {
    admin_key: utils.encodeKey(row.key),
    deleted: row.deleted,
    consensus_timestamp: utils.nsToSecNs(row.consensus_timestamp),
    creator_account_id: EntityId.parse(row.creator_account_id).toString(),
    executed_timestamp: utils.nsToSecNs(row.executed_timestamp),
    expiration_time: utils.nsToSecNs(row.expiration_time),
    memo: row.memo,
    payer_account_id: EntityId.parse(row.payer_account_id).toString(),
    schedule_id: EntityId.parse(row.schedule_id).toString(),
    signatures,
    transaction_body: utils.encodeBase64(row.transaction_body),
    wait_for_expiry: row.wait_for_expiry,
  };
};
```

**File:** rest/schedules.js (L241-264)
```javascript
  const {rows: schedules} = await pool.queryQuietly(schedulesQuery, params);

  const schedulesResponse = {schedules: [], links: {next: null}};
  res.locals[constants.responseDataLabel] = schedulesResponse;

  if (schedules.length === 0) {
    return;
  }

  const entityIds = schedules.map((s) => s.schedule_id);
  const positions = range(1, entityIds.length + 1)
    .map((i) => `$${i}`)
    .join(',');
  const entityQuery = `select ${entityFields} from entity where id in (${positions}) order by id ${order}`;
  const signatureQuery = `select entity_id, ${transactionSignatureJsonAgg} as signatures
    from transaction_signature ts
    where entity_id in (${positions})
    group by entity_id
    order by entity_id ${order}`;

  const [{rows: entities}, {rows: signatures}] = await Promise.all([
    pool.queryQuietly(entityQuery, entityIds),
    pool.queryQuietly(signatureQuery, entityIds),
  ]);
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
