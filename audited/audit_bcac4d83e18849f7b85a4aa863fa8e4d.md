### Title
Connection Pool Exhaustion DoS via Concurrent Requests to `isValidAccount()`-Dependent Endpoints

### Summary
The REST API's global `pg` connection pool is capped at 10 connections by default with a 20-second `connectionTimeoutMillis`. `isValidAccount()` in `rest/service/entityService.js` issues a synchronous DB query through `queryQuietly()`, which wraps every pool-level error — including connection-acquisition timeouts — as a `DbError`. Because no rate limiting or circuit-breaker exists, an unprivileged attacker can saturate all 10 pool slots with concurrent requests, causing every subsequent `isValidAccount()` call to throw `DbError` (HTTP 503) instead of returning a boolean, denying service to all account-validation-dependent endpoints.

### Finding Description

**Exact code path:**

`isValidAccount()` (`rest/service/entityService.js`, lines 60–63) calls `super.getSingleRow(EntityService.entityExistenceQuery, [accountId])`. [1](#0-0) 

`getSingleRow` → `getRows` → `this.pool().queryQuietly(query, params)` (`rest/service/baseService.js`, lines 55–57, 96–98). [2](#0-1) 

`queryQuietly` in `rest/utils.js` (lines 1518–1545) calls `this.query(query, params)` on the `pg` Pool. The entire try/catch unconditionally wraps **any** thrown error — including `"timeout exceeded when trying to connect"` emitted by `pg` when `connectionTimeoutMillis` expires — as `new DbError(err.message)`. [3](#0-2) 

The pool is configured in `rest/dbpool.js` with `connectionTimeoutMillis: config.db.pool.connectionTimeout` (default **20 000 ms**) and `max: config.db.pool.maxConnections` (default **10**). [4](#0-3) 

**Root cause and failed assumption:**

The design assumes the pool will always have a free slot available within `connectionTimeoutMillis`. There is no rate limiting, no concurrency cap per endpoint, and no circuit-breaker. When all 10 slots are occupied, `pg` waits up to 20 seconds and then throws; `queryQuietly` converts that into `DbError`; `isValidAccount()` propagates it uncaught. The error handler maps `DbError` to HTTP 503. [5](#0-4) 

**Callers of `isValidAccount()`:**

`accountController.js` and `tokenController.js` both call `isValidAccount()`, covering endpoints such as `/api/v1/accounts/{id}/nfts`, `/api/v1/accounts/{id}/tokens`, `/api/v1/accounts/{id}/allowances/*`, and `/api/v1/accounts/{id}/rewards`. [6](#0-5) 

**Why existing checks are insufficient:**

- No HTTP-layer rate limiting or concurrency throttle is present in `server.js`.
- `statement_timeout` (20 000 ms) means each connection can be held for up to 20 seconds under a slow or partitioned DB, making pool saturation trivially maintainable with only 10 concurrent requests.
- `isValidAccount()` has no try/catch around the `DbError` and no fallback boolean. [1](#0-0) 

### Impact Explanation
All endpoints that call `isValidAccount()` return HTTP 503 for the duration of the attack. Because the pool is shared globally, pool exhaustion also degrades every other DB-backed endpoint on the same Node.js process. The `DbError` path returns a generic 503 with no retry guidance, so legitimate clients receive hard failures rather than retryable errors.

### Likelihood Explanation
The default pool size of 10 is very small. An attacker needs only 10 concurrent HTTP connections — achievable with a single `curl`-based loop or any HTTP benchmarking tool — to saturate the pool. No authentication is required for the public REST API. The attack is repeatable and requires no special knowledge beyond the public OpenAPI spec listing the affected endpoints. [7](#0-6) 

### Recommendation
1. **Rate limiting / concurrency cap**: Add a per-IP or global concurrency limit in Express middleware (e.g., `express-rate-limit` or `bottleneck`) before DB-touching routes.
2. **Increase pool size or add a queue limit**: Raise `maxConnections` and set `pg` pool's `allowExitOnIdle` / queue depth so that excess requests are rejected fast (HTTP 429) rather than waiting 20 seconds and then failing with 503.
3. **Circuit breaker on `isValidAccount()`**: Wrap the DB call in a circuit breaker (e.g., `opossum`) so that when the pool is saturated the function short-circuits to a fast failure or cached result rather than queuing indefinitely.
4. **Distinguish pool-timeout errors from query errors**: In `queryQuietly`, detect `"timeout exceeded when trying to connect"` separately and surface it as HTTP 429 (Too Many Requests) rather than 503 (Service Unavailable), giving clients correct retry semantics. [3](#0-2) 

### Proof of Concept
```bash
# Requires: curl, GNU parallel (or any tool that fires concurrent HTTP requests)
# Target: any deployment of the REST API (default port 5551)
# No credentials needed.

BASE="http://<host>:5551/api/v1"
ACCOUNT="0.0.1234"   # any valid account id

# Step 1: Saturate the pool (10 connections, each held for up to 20 s)
# Use an account that triggers a slow query or run under DB load
for i in $(seq 1 20); do
  curl -s "${BASE}/accounts/${ACCOUNT}/nfts" &
done

# Step 2: While the above are in-flight, send a probe request
sleep 1
curl -v "${BASE}/accounts/${ACCOUNT}/tokens"
# Expected: HTTP 503 {"_status":{"messages":[{"message":"timeout exceeded when trying to connect"}]}}
# isValidAccount() threw DbError instead of returning a boolean.

wait
```

### Citations

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/utils.js (L1535-1539)
```javascript
    } catch (err) {
      if (client !== undefined) {
        await client.query('rollback');
      }
      throw new DbError(err.message);
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

**File:** rest/middleware/httpErrorHandler.js (L21-22)
```javascript
  } else if (err instanceof DbError) {
    statusCode = httpStatusCodes.SERVICE_UNAVAILABLE;
```

**File:** rest/routes/accountRoute.js (L15-19)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
router.getExt(getPath('rewards'), AccountController.listStakingRewardsByAccountId);
router.getExt(getPath('allowances/crypto'), CryptoAllowanceController.getAccountCryptoAllowances);
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
router.getExt(getPath('tokens'), TokenController.getTokenRelationships);
```

**File:** rest/api/v1/openapi.yml (L5-55)
```yaml
  /api/v1/accounts:
    get:
      summary: List account entities on network
      description: Returns a list of all account entity items on the network.
      operationId: getAccounts
      parameters:
        - $ref: "#/components/parameters/accountBalanceQueryParam"
        - $ref: "#/components/parameters/accountIdQueryParam"
        - $ref: "#/components/parameters/accountPublicKeyQueryParam"
        - $ref: "#/components/parameters/balanceQueryParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/AccountsResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
      tags:
        - accounts
  /api/v1/accounts/{idOrAliasOrEvmAddress}:
    get:
      summary: Get account by alias, id, or evm address
      description: |
        Return the account transactions and balance information given an account alias, an account id, or an evm address. The information will be limited to at most 1000 token balances for the account as outlined in HIP-367.
        When the timestamp parameter is supplied, we will return transactions and account state for the relevant timestamp query. Balance information will be accurate to within 15 minutes of the provided timestamp query.
        Historical ethereum nonce information is currently not available and may not be the exact value at a provided timestamp.
      operationId: getAccount
      parameters:
        - $ref: "#/components/parameters/accountIdOrAliasOrEvmAddressPathParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParamDesc"
        - $ref: "#/components/parameters/timestampQueryParam"
        - $ref: "#/components/parameters/transactionTypeQueryParam"
        - $ref: "#/components/parameters/transactionsQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/AccountBalanceTransactions"
        400:
          $ref: "#/components/responses/InvalidParameterError"
        404:
          $ref: "#/components/responses/NotFoundError"
      tags:
        - accounts
```
