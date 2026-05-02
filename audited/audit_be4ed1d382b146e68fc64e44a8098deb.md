### Title
Unauthenticated Flooding of `/api/v1/balances` with `account.publickey` + `timestamp` Triggers Unbounded Concurrent DB Query Chains Due to Absent Rate Limiting

### Summary
The `getBalances()` handler in `rest/balances.js` accepts `account.publickey` and `timestamp` filters from any unauthenticated caller. Each such request triggers a sequential chain of at least three database queries — including a correlated per-row `token_balance` subquery that executes up to 100 times per request — with no per-IP or per-endpoint rate limiting present anywhere in the REST API layer. An attacker can sustain a high volume of concurrent requests to exhaust DB connection pool and CPU, degrading response times for all users.

### Finding Description

**Code path:**

`rest/balances.js`, `getBalances()` (lines 83–156) and `getAccountIdsByPublicKey()` (lines 60–76). [1](#0-0) 

**Per-request DB query chain (when `timestamp` + `account.publickey` are both supplied):**

1. **`getAccountBalanceTimestampRange`** (line 114): queries `account_balance` for the treasury account to resolve a snapshot timestamp range.
2. **`getAccountIdsByPublicKey`** (line 119): queries `entity` table:
   ```sql
   select id from entity where type in ('ACCOUNT', 'CONTRACT') and public_key = $1 limit $2
   ```
   `$2` is the user-supplied `limit`, capped at 100. The entity table has an index `entity__public_key_type on entity(public_key, type)`, so this lookup is fast. [2](#0-1) 

3. **Main `account_balance` query** (lines 207–216 via `getBalancesQuery`): scans `account_balance` with `account_id IN (<up to 100 IDs>)` and a 2-month timestamp range, using `distinct on (account_id)` with `order by account_id, consensus_timestamp desc`. [3](#0-2) 

4. **Correlated `token_balance` subquery** (lines 294–306): executes once **per result row** (up to 100 rows), each performing a `distinct on (token_id)` scan of `token_balance` for that account within the timestamp range, limited to 50 token balances per account: [4](#0-3) 

   This means a single request at `limit=100` can trigger up to **100 correlated subqueries** against `token_balance`.

**Root cause — no rate limiting in the REST API:**

The `web3` module has a `ThrottleConfiguration` with bucket4j rate limiting, but the Node.js REST API has **no equivalent**. A search of `rest/**/*.js` for `rateLimit`, `rateLimiter`, or `throttle` returns only a single test utility match — no production middleware. The only protection is the `limit` cap (default max 100, configurable). [5](#0-4) 

The documentation confirms `hiero.mirror.rest.response.limit.max` defaults to 100 with no mention of request-rate controls for the REST API.

**Failed assumption:** The design assumes the `limit` cap on result rows is sufficient to bound per-request DB cost. It does not account for the multiplicative effect of the correlated `token_balance` subquery (up to 100 × 50 = 5,000 token balance lookups per request) nor for the absence of any request-rate control allowing unlimited concurrent requests.

### Impact Explanation

Each request at `limit=100` with a valid `account.publickey` and current `timestamp` causes:
- 3 sequential DB round-trips before the main query
- 1 main `account_balance` query across up to 2 monthly partitions
- Up to 100 correlated `token_balance` subqueries

Flooding with N concurrent requests multiplies this load by N. The DB connection pool (`db.pool.maxConnections`) becomes saturated, statement timeouts (`db.pool.statementTimeout`) begin firing, and all other API endpoints sharing the same DB pool experience elevated latency or errors. No economic damage occurs to network participants, consistent with the Medium/griefing scope.

### Likelihood Explanation

Preconditions are minimal: the attacker needs only a valid public key (obtainable from any account lookup on the public API) and a recent timestamp. No authentication, no tokens, no privileged access. The attack is trivially scriptable with any HTTP load tool (`ab`, `wrk`, `hey`). It is repeatable indefinitely.

### Recommendation

1. **Add per-IP rate limiting middleware** to the REST API (e.g., `express-rate-limit` or a Redis-backed sliding window) specifically for expensive filter combinations (`account.publickey` + `timestamp`).
2. **Require at least one of `account.id` or `account.publickey` to be an equality filter** when `timestamp` is present, to ensure the `account_id IN (...)` list is small.
3. **Move the correlated `token_balance` subquery to a single batch query** (e.g., a lateral join or a separate query with `account_id = ANY(...)`) to eliminate the N×M query fan-out.
4. **Set a DB-level `statement_timeout`** for the REST API role to bound worst-case query duration.

### Proof of Concept

```bash
# 1. Obtain any valid public key from the network
PK=$(curl -s "https://<mirror>/api/v1/accounts?limit=1" | jq -r '.accounts[0].key.key')

# 2. Get a valid recent timestamp
TS=$(curl -s "https://<mirror>/api/v1/blocks?limit=1&order=desc" | jq -r '.blocks[0].consensus_end')

# 3. Flood with maximum limit + publickey + timestamp (no auth required)
hey -n 10000 -c 200 \
  "https://<mirror>/api/v1/balances?account.publickey=${PK}&timestamp=lte:${TS}&limit=100"
```

Each of the 200 concurrent workers issues a request that triggers the 3-query chain plus up to 100 correlated subqueries. Observe DB CPU and connection pool saturation; other endpoints (`/api/v1/transactions`, `/api/v1/accounts`) will show increased latency or `503` responses as the pool exhausts.

### Citations

**File:** rest/balances.js (L58-76)
```javascript
const entityPublicKeyQuery = `select id from entity where type in ('ACCOUNT', 'CONTRACT') and public_key = $1 limit $2`;

const getAccountIdsByPublicKey = async (publicKey, limit) => {
  if (isEmpty(publicKey)) {
    return null;
  }

  const params = [...publicKey, limit];
  const result = await pool.queryQuietly(entityPublicKeyQuery, params);

  if (result) {
    const ids = result.rows.map((r) => r.id);
    if (!isEmpty(ids)) {
      return `ab.account_id in (${ids})`;
    }
  }

  return null;
};
```

**File:** rest/balances.js (L83-156)
```javascript
const getBalances = async (req, res) => {
  utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator);

  // Parse the filter parameters for credit/debit, account-numbers, timestamp and pagination
  const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
  const accountParams = await Promise.all(accountParamsPromise);
  // transform the timestamp=xxxx or timestamp=eq:xxxx query in url to 'timestamp <= xxxx' SQL query condition
  let [tsQuery, tsParams] = utils.parseTimestampQueryParam(req.query, 'consensus_timestamp', {
    [utils.opsMap.eq]: utils.opsMap.lte,
  });
  const [balanceQuery, balanceParams] = utils.parseBalanceQueryParam(req.query, 'ab.balance');
  const [pubKeyQuery, pubKeyParams] = utils.parsePublicKeyQueryParam(req.query, 'public_key');
  const {
    query: limitQuery,
    params,
    order,
    limit,
  } = utils.parseLimitAndOrderParams(req, constants.orderFilterValues.DESC);

  res.locals[constants.responseDataLabel] = {
    timestamp: null,
    balances: [],
    links: {
      next: null,
    },
  };

  let sqlQuery;
  let sqlParams;

  if (tsQuery) {
    const tsQueryResult = await getTsQuery(tsQuery, tsParams);
    if (!tsQueryResult.query) {
      return;
    }

    const accountIdsQuery = await getAccountIdsByPublicKey(pubKeyParams, limit);
    if (pubKeyQuery && !accountIdsQuery) {
      return;
    }

    [sqlQuery, tsParams] = await getBalancesQuery(
      accountQuery,
      balanceQuery,
      accountIdsQuery,
      limitQuery,
      order,
      tsQueryResult
    );
    sqlParams = utils.mergeParams(tsParams, accountParams, balanceParams, params);
  } else {
    // use current balance from entity table when there's no timestamp query filter
    const conditions = [accountQuery, pubKeyQuery, balanceQuery].filter(Boolean).join(' and ');
    const whereClause = conditions && `where ${conditions}`;
    const tokenBalanceSubQuery = getTokenAccountBalanceSubQuery(order);
    sqlParams = utils.mergeParams(tsParams, accountParams, pubKeyParams, balanceParams, params);
    sqlQuery = `
      with entity_balance as (
        select id as account_id, balance, balance_timestamp as consensus_timestamp, public_key
        from entity
        where type in ('ACCOUNT', 'CONTRACT')
      )
      select ab.*, (${tokenBalanceSubQuery}) as token_balances
      from entity_balance ab
      ${whereClause}
      order by ab.account_id ${order}
      ${limitQuery}`;
  }

  const pgSqlQuery = utils.convertMySqlStyleQueryToPostgres(sqlQuery);
  const result = await pool.queryQuietly(pgSqlQuery, sqlParams);
  res.locals[constants.responseDataLabel] = formatBalancesResult(req, result, limit, order);
  logger.debug(`getBalances returning ${result.rows.length} entries`);
};
```

**File:** rest/balances.js (L199-218)
```javascript
const getBalancesQuery = async (accountQuery, balanceQuery, accountIdsQuery, limitQuery, order, tsQueryResult) => {
  const tokenBalanceSubQuery = getTokenBalanceSubQuery(order, tsQueryResult.query);
  const whereClause = `
      where ${[tsQueryResult.query, accountQuery, accountIdsQuery, balanceQuery].filter(Boolean).join(' and ')}`;
  const {lower, upper} = tsQueryResult.timestampRange;
  // The first upper is for the consensus_timestamp in the select fields, also double the lower and the upper since
  // they are used twice, in the token balance subquery and in the where clause of the main query
  const tsParams = [upper, lower, upper, lower, upper];
  const sqlQuery = `
      select distinct on (account_id)
        ab.account_id,
        ab.balance,
        ?::bigint as consensus_timestamp,
        (${tokenBalanceSubQuery}) as token_balances
      from account_balance ab
      ${whereClause}
      order by ab.account_id ${order}, ab.consensus_timestamp desc
      ${limitQuery}`;
  return [sqlQuery, tsParams];
};
```

**File:** rest/balances.js (L294-306)
```javascript
const getTokenBalanceSubQuery = (order, consensusTsQuery) => {
  consensusTsQuery = consensusTsQuery.replaceAll('ab.', 'tb.');
  return `
    select json_agg(json_build_object('token_id', token_id, 'balance', balance))
    from (
      select distinct on (token_id) token_id, balance
      from token_balance tb
      where tb.account_id = ab.account_id
        and ${consensusTsQuery}
      order by token_id ${order}, consensus_timestamp desc
      limit ${tokenBalanceLimit.multipleAccounts}
    ) as account_token_balance`;
};
```

**File:** rest/config.js (L133-135)
```javascript
function getResponseLimit() {
  return getConfig().response.limit;
}
```
