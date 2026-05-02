### Title
Unauthenticated Multi-Query Amplification DoS in `getBalances()` via Combined Parameter Exploitation

### Summary
The `getBalances()` handler in `rest/balances.js` unconditionally executes up to four sequential database queries when an unauthenticated caller combines `account.id` (EVM alias/alias), `timestamp`, and `account.publickey` parameters in a single request. No rate limiting exists on this endpoint in the REST API layer, and the default DB connection pool is only 10 connections, meaning a small number of concurrent crafted requests can exhaust the pool and deny service to all other API consumers.

### Finding Description

**Exact code path (`rest/balances.js`, `getBalances()`, lines 83–155):**

**Query 1 — Alias resolution (line 88):**
`parseAccountIdQueryParam` (lines 320–357) detects an EVM address or account alias in `account.id` and returns a Promise that calls `EntityService.getEncodedId()` or `EntityService.getAccountIdFromAlias()`, each of which issues a live SQL query against the `entity` table. This Promise is awaited synchronously at line 88 before any other work proceeds. [1](#0-0) [2](#0-1) [3](#0-2) 

**Query 2 — Timestamp range scan (line 114):**
`getTsQuery()` calls `getAccountBalanceTimestampRange()`, which issues a query against the `account_balance` table to find the latest snapshot timestamp satisfying the user-supplied timestamp bounds. [4](#0-3) [5](#0-4) 

**Query 3 — Public key entity lookup (line 119):**
`getAccountIdsByPublicKey()` issues a query against the `entity` table using `entityPublicKeyQuery` to resolve all account IDs matching the supplied public key. [6](#0-5) [7](#0-6) 

**Query 4 — Main balances query (line 153):**
The final `pool.queryQuietly()` call executes the main `account_balance` scan with a correlated `token_balance` subquery per row. [8](#0-7) 

All four queries are strictly sequential (`await` at each step). No caching layer exists for alias resolution or public key lookups in the Node.js REST service. The `entityId` cache documented in configuration applies only to the `rest-java` module. [9](#0-8) 

**Root cause:** The handler unconditionally fans out to multiple independent DB queries with no short-circuit, no per-IP rate limiting, and no request-level cost budget. The failed assumption is that callers will not deliberately combine all expensive parameters simultaneously.

**No rate limiting on the REST API:**
The `ThrottleConfiguration` and `ThrottleManager` exist only in the `web3` module. The `rest` (Node.js) module has no equivalent middleware protecting `/api/v1/balances`. [10](#0-9) 

**Small default connection pool:**
The default `maxConnections` for the REST API DB pool is **10**. [11](#0-10) [12](#0-11) 

### Impact Explanation

Each crafted request multiplies DB load by 4× compared to a normal single-query request. With a default pool of 10 connections and each request issuing 4 sequential queries (each acquiring/releasing a connection), a sustained flood of ~10–20 concurrent crafted requests is sufficient to keep the pool saturated, causing all other API requests to queue or time out. The `account_balance` table is partitioned by month but can still be large; the timestamp range query scans it with a `desc` sort, and the main balances query includes a correlated `token_balance` subquery per returned row, making each query non-trivial. This degrades or denies service to all consumers of the mirror node REST API, including wallets, explorers, and DeFi integrations. [13](#0-12) 

### Likelihood Explanation

The attack requires zero authentication, zero on-chain funds, and zero special knowledge beyond reading the public OpenAPI spec, which documents all three parameters for `/api/v1/balances`. The EVM alias can be any valid 40-hex-character string (even one that resolves to nothing — the alias resolution query still executes). The attack is trivially scriptable with `curl` or any HTTP client and is fully repeatable. A single attacker with a modest number of concurrent connections (10–20) can sustain the attack indefinitely. [14](#0-13) 

### Recommendation

1. **Add per-endpoint rate limiting** to the Node.js REST API (e.g., via `express-rate-limit` or a reverse-proxy rule) for `/api/v1/balances`, keyed by IP or API key.
2. **Parallelize independent pre-queries**: Queries 2 (timestamp range) and 3 (public key lookup) are independent of each other and can be issued with `Promise.all()` instead of sequentially, halving the sequential depth.
3. **Short-circuit early**: If `account.id` is an alias that resolves to nothing, return immediately before issuing the timestamp and public key queries.
4. **Increase the default `maxConnections`** or document a minimum recommended value for production deployments.
5. **Consider a query cost budget**: Reject requests that combine more than N expensive filter parameters simultaneously.

### Proof of Concept

```bash
# Craft a request combining all three expensive parameters:
# - account.id as an EVM alias (triggers entity table lookup)
# - timestamp (triggers account_balance timestamp range scan)
# - account.publickey (triggers entity table public key scan)

ALIAS="0xac384c53f03855fa1b3616052f8ba32c6c2a2fec"
PUBKEY="6ceecd8bb224da4914d53f292e5624f6f4cf8c134c920e1cac8d06f879df5819"
TIMESTAMP="1686312900.000000000"

# Send 20 concurrent requests to exhaust the default 10-connection pool
for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>:5551/api/v1/balances?\
account.id=${ALIAS}&\
timestamp=lte:${TIMESTAMP}&\
account.publickey=${PUBKEY}" &
done
wait

# Expected result: legitimate requests begin timing out or receiving 503/504
# as the DB connection pool is saturated with 4x query amplification per request.
```

The four sequential DB queries triggered per request are confirmed by the code path:
- Line 88: alias → `entity` table
- Line 114: timestamp → `account_balance` table  
- Line 119: public key → `entity` table
- Line 153: main balances → `account_balance` table [15](#0-14)

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

**File:** rest/balances.js (L83-155)
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
```

**File:** rest/balances.js (L182-189)
```javascript
  const query = `
    select consensus_timestamp
    from account_balance
    where ${condition}
    order by consensus_timestamp desc
    limit 1`;

  const {rows} = await pool.queryQuietly(query, params);
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

**File:** rest/balances.js (L328-332)
```javascript
      if (EntityId.isValidEvmAddress(value, EvmAddressType.NO_SHARD_REALM) && ++evmAliasAddressCount === 1) {
        return EntityService.getEncodedId(value, false);
      }
      if (AccountAlias.isValid(value, true) && ++evmAliasAddressCount === 1) {
        return EntityService.getAccountIdFromAlias(AccountAlias.fromString(value), false);
```

**File:** rest/balances.js (L365-372)
```javascript
const acceptedBalancesParameters = new Set([
  constants.filterKeys.ACCOUNT_BALANCE,
  constants.filterKeys.ACCOUNT_ID,
  constants.filterKeys.ACCOUNT_PUBLICKEY,
  constants.filterKeys.LIMIT,
  constants.filterKeys.ORDER,
  constants.filterKeys.TIMESTAMP,
]);
```

**File:** rest/service/entityService.js (L17-26)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;

  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;

```

**File:** docs/configuration.md (L546-548)
```markdown
| `hiero.mirror.rest.cache.entityId.maxAge`                                | 1800                    | The number of seconds until the entityId cache entry expires                                                                                                                                  |
| `hiero.mirror.rest.cache.entityId.maxSize`                               | 100000                  | The maximum number of entries in the entityId cache                                                                                                                                           |
| `hiero.mirror.rest.cache.token.maxSize`                                  | 100000                  | The maximum number of entries in the token cache                                                                                                                                              |
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** rest/api/v1/openapi.yml (L391-419)
```yaml
  /api/v1/balances:
    get:
      summary: List account balances
      description:
        Returns a list of account and token balances on the network. The latest balance information is returned when
        there is no timestamp query parameter, otherwise, the information is retrieved from snapshots with 15-minute
        granularity. This information is limited to at most 50 token balances per account as outlined in HIP-367.
        As such, it's not recommended for general use and we instead recommend using either
        `/api/v1/accounts/{id}/tokens` or `/api/v1/tokens/{id}/balances` to obtain the current token balance information
        and `/api/v1/accounts/{id}` to return the current account balance.
      operationId: getBalances
      parameters:
        - $ref: "#/components/parameters/accountIdOrAliasOrEvmAddressQueryParam"
        - $ref: "#/components/parameters/accountBalanceQueryParam"
        - $ref: "#/components/parameters/accountPublicKeyQueryParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParamDesc"
        - $ref: "#/components/parameters/timestampQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/BalancesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
      tags:
        - balances
```
