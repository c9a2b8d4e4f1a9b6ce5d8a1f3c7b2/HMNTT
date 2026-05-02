### Title
Unbounded `token_account` Full-Table Scan in `getAccounts()` Enables Unauthenticated DoS via Concurrent Requests

### Summary
The `getEntityBalanceQuery()` function in `rest/accounts.js` constructs a `with latest_token_balance as (select ... from token_account where associated is true)` CTE with no `LIMIT` clause and no account-scoping filter, causing a full sequential scan of the entire `token_account` table on every request where `balance=true` and no timestamp filter is supplied. Because the REST API has no rate-limiting or concurrency control on the `/api/v1/accounts` endpoint, any unauthenticated attacker can flood the endpoint with concurrent maximum-limit requests, saturating database I/O and starving the importer of the bandwidth it needs to write gossip transaction data.

### Finding Description

**Exact code path:**

`rest/accounts.js`, function `getEntityBalanceQuery()`, lines 183–186:

```js
queries.push(`with latest_token_balance as (
   select account_id, balance, token_id
   from token_account
   where associated is true)`);
``` [1](#0-0) 

This CTE is emitted whenever `needHistoricalBalanceInfo` is falsy, which is the default path for every request that omits a `timestamp` query parameter:

```js
const needHistoricalBalanceInfo = accountBalanceQuery.query || accountBalanceQuery.forceUnionEntityHistory;
``` [2](#0-1) 

When `balance=true` (the default) and no `timestamp` is given, `accountBalanceQuery` is `{query: '', params: []}`, so `needHistoricalBalanceInfo` is `''` (falsy), and the CTE branch is always taken.

**Root cause:** The CTE itself carries no `LIMIT` and no `account_id` predicate. The `LIMIT` that does exist (`limit ${tokenBalanceQuery.limit}`) is applied only to the *outer* subquery that reads from the CTE, not to the CTE's own scan:

```js
selectTokenBalance = `(select json_agg(...) from (
    select token_id, balance
    from latest_token_balance
    where ${tokenBalanceQuery.query}
    order by token_id ${order}
    limit ${tokenBalanceQuery.limit}   // ← limits tokens per account, NOT the CTE scan
  ) as account_token_balance) as token_balances`;
``` [3](#0-2) 

PostgreSQL materialises the CTE (or at minimum scans the full `token_account` table to satisfy it) before the outer filter is applied. With millions of token-account rows this is a full sequential I/O scan per request.

**No rate limiting on the accounts endpoint:** `rest/server.js` registers the route with no throttle middleware:

```js
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
``` [4](#0-3) 

The only throttling in the codebase is in the `web3` Java service (`ThrottleManagerImpl`), which is entirely separate from this Node.js REST API. [5](#0-4) 

The `authHandler` middleware only enforces per-user *response-size* limits, not request rate or concurrency limits. [6](#0-5) 

**Configuration confirms the attack surface:** Default max limit is 100 accounts; `tokenBalance.multipleAccounts` is 50. Neither cap bounds the CTE scan. [7](#0-6) 

### Impact Explanation
Each concurrent `GET /api/v1/accounts?balance=true&limit=100` request issues a full sequential scan of `token_account` (potentially tens of millions of rows on mainnet). With N concurrent requests, N simultaneous full scans compete for the same disk/buffer-pool I/O. The Hiero importer writes gossip transaction records to the same PostgreSQL instance; when I/O bandwidth is saturated, importer `INSERT`/`UPDATE` operations queue behind the scan I/O, causing write latency spikes or timeouts. This delays or drops gossip transaction data from being persisted, breaking the mirror node's core function. Severity: **High** — unauthenticated, no special account needed, directly impacts data integrity of the mirror node.

### Likelihood Explanation
The attack requires only an HTTP client and knowledge of the public API (documented in OpenAPI spec). No authentication, no tokens, no privileged access. The endpoint is publicly reachable. A single attacker with a modest number of concurrent connections (e.g., 20–50) is sufficient to trigger the condition on a production database with a large `token_account` table. The attack is trivially repeatable and scriptable.

### Recommendation
1. **Add a `LIMIT` to the CTE itself**, scoped to the accounts being queried. Pass the account IDs from the outer entity query into the CTE so it reads only relevant rows:
   ```sql
   with latest_token_balance as (
     select account_id, balance, token_id
     from token_account
     where associated is true
       and account_id = ANY($account_ids_array)
   )
   ```
2. **Add per-IP rate limiting / concurrency limiting** middleware to the Node.js REST API (e.g., `express-rate-limit`) for the `/api/v1/accounts` endpoint.
3. **Set a PostgreSQL `statement_timeout`** for the REST API database role to bound the maximum duration of any single query.
4. **Consider a DB connection pool cap** for the REST API so that a flood of requests cannot hold more than N simultaneous DB connections.

### Proof of Concept
```bash
# Fire 50 concurrent requests with maximum limit and balance=true (no timestamp = CTE path)
for i in $(seq 1 50); do
  curl -s "https://<mirror-node-host>/api/v1/accounts?balance=true&limit=100" \
    -o /dev/null &
done
wait

# Observe on the PostgreSQL host:
# SELECT query, state, wait_event_type, wait_event
# FROM pg_stat_activity
# WHERE query LIKE '%latest_token_balance%';
# → 50 rows, all in state 'active', wait_event_type 'IO'

# Simultaneously monitor importer write latency:
# SELECT * FROM pg_stat_activity WHERE application_name = 'importer';
# → queries queued / timing out due to I/O starvation
```

### Citations

**File:** rest/accounts.js (L164-164)
```javascript
  const needHistoricalBalanceInfo = accountBalanceQuery.query || accountBalanceQuery.forceUnionEntityHistory;
```

**File:** rest/accounts.js (L183-186)
```javascript
    queries.push(`with latest_token_balance as (
       select account_id, balance, token_id
       from token_account
       where associated is true)`);
```

**File:** rest/accounts.js (L187-195)
```javascript
    selectTokenBalance = `(select json_agg(jsonb_build_object('token_id', token_id, 'balance', balance)) ::jsonb
          from (
            select token_id, balance
            from latest_token_balance
            where ${tokenBalanceQuery.query}
            order by token_id ${order}
            limit ${tokenBalanceQuery.limit}
          ) as account_token_balance)
        as token_balances`;
```

**File:** rest/server.js (L85-87)
```javascript
// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

```

**File:** rest/server.js (L101-101)
```javascript
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-43)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

```

**File:** docs/configuration.md (L607-610)
```markdown
| `hiero.mirror.rest.response.limit.default`                               | 25                      | The default value for the limit parameter that controls the REST API response size                                                                                                            |
| `hiero.mirror.rest.response.limit.max`                                   | 100                     | The maximum size the limit parameter can be that controls the REST API response size                                                                                                          |
| `hiero.mirror.rest.response.limit.tokenBalance.multipleAccounts`         | 50                      | The maximum number of token balances per account for endpoints which return such info for multiple accounts                                                                                   |
| `hiero.mirror.rest.response.limit.tokenBalance.singleAccount`            | 1000                    | The maximum number of token balances per account for endpoints which return such info for a single account                                                                                    |
```
