### Title
Unauthenticated DB Connection Pool Exhaustion via Uncached NOT_FOUND Lookups Using `filterKeys.NONCE`

### Summary
The REST API's transaction-by-ID endpoint accepts `nonce=2147483647` (MAX_INT32) as a valid query parameter with no rate limiting applied at the Node.js layer. Because 404 NOT_FOUND responses are explicitly excluded from the Redis response cache, every request for a non-existent transaction ID with a valid nonce value triggers a live DB query. With a default pool of only 10 connections, a low-volume flood of concurrent unauthenticated requests is sufficient to exhaust the pool and produce `httpStatusCodes.SERVICE_UNAVAILABLE` (503) for all users.

### Finding Description

**Validation allows MAX_INT32 — no rejection:**

In `rest/utils.js`, the `filterValidityChecks` function validates the NONCE parameter:

```js
case constants.filterKeys.NONCE:
  ret = op === constants.queryParamOperators.eq && isNonNegativeInt32(val);
  break;
```

The test suite at `rest/__tests__/utilsFilters.test.js` lines 660–663 explicitly confirms `'2147483647'` is a **valid** value and `'2147483648'` is invalid. So MAX_INT32 passes validation cleanly.

**Query always hits the DB for non-existent transactions:**

In `rest/transactions.js`, `extractSqlFromTransactionsByIdOrHashRequest` (lines 763–795) builds a parameterized SQL query including `nonce = $N` and executes it against the DB. If no row matches, it returns an empty result set → `NotFoundError` → HTTP 404.

**404 responses are never cached:**

In `rest/middleware/responseCacheHandler.js` line 95:
```js
if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```
Only 2xx/304 responses are stored in Redis. Every NOT_FOUND response bypasses the cache entirely, so each attacker request causes a fresh DB round-trip.

**No rate limiting exists in the Node.js REST API:**

`rest/middleware/index.js` exports: `authHandler`, `handleError`, `openApiValidator`, `requestHandler`, `responseCacheHandler`, `responseHandler` — no rate limiter. A grep across all `rest/**/*.js` for `rateLimit|throttle` returns only a single match in a test utility file. The throttle infrastructure found in `web3/` (Java, `ThrottleManagerImpl.java`) is entirely separate and does not apply to the Node.js REST service.

**Tiny default DB connection pool:**

`docs/configuration.md` line 556:
```
hiero.mirror.rest.db.pool.maxConnections | 10
```
`rest/dbpool.js` line 14: `max: config.db.pool.maxConnections`

With `statementTimeout` defaulting to 20,000 ms and `connectionTimeout` also 20,000 ms, each in-flight DB query holds a connection for up to 20 seconds. Ten concurrent requests for non-existent transactions saturate the pool; subsequent requests queue and then time out, producing 503 responses.

### Impact Explanation

A complete DB connection pool exhaustion causes `httpStatusCodes.SERVICE_UNAVAILABLE` (503) for **all** API consumers — not just the attacker. This constitutes a network partition from the perspective of any client depending on the mirror node REST API (wallets, explorers, dApps). The default pool size of 10 makes this trivially achievable with minimal request volume, and the 20-second statement timeout means each connection is held long enough to sustain the exhaustion with very few concurrent connections.

### Likelihood Explanation

No authentication, API key, or proof-of-work is required. The attacker needs only:
- Knowledge of any valid transaction ID format (publicly documented)
- The ability to send ~10–20 concurrent HTTP requests

This is achievable by any script kiddie with `curl` or `ab`. The attack is repeatable indefinitely and requires no special network position. The absence of any per-IP or global rate limiter in the Node.js REST middleware stack means there is no automatic circuit breaker.

### Recommendation

1. **Add rate limiting middleware** to the Node.js REST API (e.g., `express-rate-limit`) applied globally before route handlers, with per-IP limits.
2. **Cache negative (404) responses** for a short TTL (e.g., 5–10 seconds) in Redis to prevent repeated DB hits for the same non-existent resource.
3. **Increase the default pool size** or add a connection acquisition timeout that returns 503 early rather than holding the request for 20 seconds, reducing the amplification window.
4. **Add a query result short-circuit**: before executing the full transaction query, perform a cheap existence check (e.g., index-only scan on `payer_account_id + valid_start_ns`) and return 404 immediately if no base record exists, without joining additional tables.

### Proof of Concept

```bash
# Generate a syntactically valid but non-existent transaction ID
TX_ID="0.0.999999999-999999999-999999999"

# Flood with 20 concurrent requests, each holding a DB connection
for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>:5551/api/v1/transactions/${TX_ID}?nonce=2147483647" &
done
wait

# All subsequent legitimate requests now receive 503
curl -v "http://<mirror-node-host>:5551/api/v1/transactions/0.0.1-1234567890-000000000"
# Expected: HTTP/1.1 503 Service Unavailable
```

The 20 concurrent requests exhaust the 10-connection pool (with headroom for the connection timeout window), and legitimate users receive 503 until the attacker's connections drain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** rest/utils.js (L333-335)
```javascript
    case constants.filterKeys.NONCE:
      ret = op === constants.queryParamOperators.eq && isNonNegativeInt32(val);
      break;
```

**File:** rest/__tests__/utilsFilters.test.js (L645-667)
```javascript
describe('utils validateAndParseFilters nonce key tests', () => {
  const key = constants.filterKeys.NONCE;
  const invalidFilters = [
    // erroneous data
    utils.buildComparatorFilter(key, '-1'),
    utils.buildComparatorFilter(key, '2147483648'),
    // invalid format
    utils.buildComparatorFilter(key, 'x'),
    // invalid op
    utils.buildComparatorFilter(key, 'ge:0'),
    utils.buildComparatorFilter(key, 'gte:0'),
    utils.buildComparatorFilter(key, 'le:0'),
    utils.buildComparatorFilter(key, 'lte:0'),
  ];

  const filters = [
    utils.buildComparatorFilter(key, '0'),
    utils.buildComparatorFilter(key, '2147483647'),
    utils.buildComparatorFilter(key, 'eq:0'),
  ];

  verifyValidAndInvalidFilters(invalidFilters, filters);
});
```

**File:** rest/middleware/responseCacheHandler.js (L90-96)
```javascript
const responseCacheUpdateHandler = async (req, res) => {
  const responseCacheKey = res.locals[responseCacheKeyLabel];
  const responseBody = res.locals[responseBodyLabel];
  const isUnmodified = res.statusCode === httpStatusCodes.UNMODIFIED.code;

  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** rest/transactions.js (L763-795)
```javascript
const extractSqlFromTransactionsByIdOrHashRequest = async (transactionIdOrHash, filters) => {
  const isTransactionHash = isValidTransactionHash(transactionIdOrHash);

  if (isTransactionHash) {
    const encoding = transactionIdOrHash.length === Transaction.BASE64_HASH_SIZE ? 'base64url' : 'hex';
    if (transactionIdOrHash.length === Transaction.HEX_HASH_WITH_PREFIX_SIZE) {
      transactionIdOrHash = transactionIdOrHash.substring(2);
    }

    const rows = await getTransactionHash(Buffer.from(transactionIdOrHash, encoding));
    if (rows.length === 0) {
      throw new NotFoundError();
    }

    const payerAccountId = rows[0].payer_account_id;
    const lookupKeys = rows.map((row) => [payerAccountId, row.consensus_timestamp]).flat();

    return {
      ...getTransactionsByTransactionIdsSql(lookupKeys, filters, Transaction.CONSENSUS_TIMESTAMP),
      isTransactionHash,
    };
  } else {
    // try to parse it as a transaction id
    const transactionId = TransactionId.fromString(transactionIdOrHash);
    const payerAccountId = BigInt(transactionId.getEntityId().getEncodedId());
    const validStartTimestamp = BigInt(transactionId.getValidStartNs());

    return {
      ...getTransactionsByTransactionIdsSql([payerAccountId, validStartTimestamp], filters, Transaction.VALID_START_NS),
      isTransactionHash,
    };
  }
};
```

**File:** rest/constants.js (L8-8)
```javascript
const MAX_INT32 = 2147483647;
```
