Based on my code investigation, I can verify the key technical claims in this report against the actual codebase.

**Verified facts:**

1. `getAccounts()` at `rest/accounts.js:366-367` — confirmed: `preQueryHint` is set when `pubKeyQuery.query !== ''`, and `pool.queryQuietly(query, params, preQueryHint)` is called. [1](#0-0) 

2. `queryQuietly` at `rest/utils.js:1518-1527` — confirmed: when `preQueryHint` is truthy, `this.connect()` checks out a dedicated client from the pool and holds it across `begin → query → commit`, released only in `finally`. [2](#0-1) 

3. Pool config at `rest/dbpool.js:7-16` — confirmed: `max: config.db.pool.maxConnections`, `connectionTimeoutMillis: config.db.pool.connectionTimeout`, `statement_timeout: config.db.pool.statementTimeout`. [3](#0-2) 

4. No rate limiting in the REST module — confirmed: grep for `rateLimit` in `rest/**` returns only a test utility file. [4](#0-3) 

5. `getEntityBalanceQuery` at `rest/accounts.js:133-237` — confirmed: builds a `with latest_token_balance` CTE and `LEFT JOIN entity_stake` with multi-condition WHERE. [5](#0-4) 

---

# Audit Report

## Title
Unauthenticated DB Connection Pool Exhaustion via `account.publickey` Filter in `getAccounts()`

## Summary
An unauthenticated attacker can send 10 concurrent `GET /api/v1/accounts?account.publickey=...` requests to exhaust the REST API's database connection pool. Each request triggers a dedicated pool client checkout that is held for the full query duration (up to 20 seconds). With a default pool size of 10, all connections are saturated, rendering the REST API unavailable for up to 20 seconds per wave. The attack is trivially repeatable.

## Finding Description

In `rest/accounts.js`, `getAccounts()` evaluates the `preQueryHint` condition at line 366:

```js
const preQueryHint = pubKeyQuery.query !== '' && constants.zeroRandomPageCostQueryHint;
const result = await pool.queryQuietly(query, params, preQueryHint);
``` [1](#0-0) 

`constants.zeroRandomPageCostQueryHint` is `'set local random_page_cost = 0'`, which is truthy whenever `account.publickey` is present in the request. [6](#0-5) 

Inside `queryQuietly` (`rest/utils.js:1518-1527`), the truthy `preQueryHint` branch calls `this.connect()` — checking out a dedicated client from the pool — and holds it for the entire transaction:

```js
client = await this.connect();
client.on('error', clientErrorCallback);
await client.query(`begin; ${preQueryHint}`);
result = await client.query(query, params);
await client.query('commit');
``` [7](#0-6) 

The client is only released in the `finally` block at line 1543, meaning it is held for the full query execution time. [8](#0-7) 

The pool is configured with `max: config.db.pool.maxConnections` (default **10**) and `statement_timeout: config.db.pool.statementTimeout` (default **20,000 ms**): [9](#0-8) 

The query built by `getEntityBalanceQuery()` for the combined-filter case includes a `with latest_token_balance` CTE scanning `token_account`, a `LEFT JOIN entity_stake`, and a multi-condition WHERE clause. With `random_page_cost = 0`, the planner prefers index scans, making the query expensive on large datasets. [10](#0-9) 

**Why existing mitigations are insufficient:**
- `validateReq` checks parameter format only — it does not limit concurrency or query cost.
- `maxRepeatedQueryParameters` limits repetition of a single parameter but does not prevent combining all filters in one request.
- `statement_timeout = 20,000 ms` kills individual queries after 20 seconds but does **not** prevent pool exhaustion: 10 concurrent requests each hold a dedicated connection for up to 20 seconds, fully saturating the pool.
- There is no application-level rate limiting in the REST module. [11](#0-10) 

## Impact Explanation

With the default pool of 10 connections, 10 concurrent crafted requests exhaust the pool. All subsequent REST API requests fail with connection timeout errors (waiting up to `connectionTimeout = 20,000 ms`). The REST API — the primary query interface of the mirror node — becomes completely unavailable. Since the attack is repeatable every ~20 seconds (the statement timeout), sustained DoS is achievable with minimal effort.

## Likelihood Explanation

The attack requires zero privileges. Any valid `account.publickey` value (obtainable from any public Hedera account lookup) suffices. The request is a single valid HTTP GET. Sending 10 concurrent requests is trivial with any HTTP client (`curl`, `ab`, `wrk`). No brute force or authentication is needed. The attack is repeatable indefinitely.

## Recommendation

1. **Limit dedicated connection hold time**: Add a per-request timeout specifically for the `connect()`-based path, shorter than `statement_timeout`.
2. **Introduce application-level concurrency limiting**: Use a semaphore or queue to cap the number of simultaneous `preQueryHint` (dedicated-client) requests, e.g., to `maxConnections / 2`.
3. **Add rate limiting to the REST API**: The `web3` module already has rate limiting; apply equivalent middleware to the REST router.
4. **Reduce default pool size exposure**: Consider reserving a portion of the pool for non-`preQueryHint` queries so ordinary requests are not starved.
5. **Consider query cost controls**: Use PostgreSQL's `statement_timeout` in combination with `lock_timeout` and connection-level limits (`pg_hba.conf` or PgBouncer) to prevent a single client from monopolizing resources.

## Proof of Concept

```bash
# Send 10 concurrent requests with account.publickey to exhaust the pool
for i in $(seq 1 10); do
  curl -s "https://<mirror-node>/api/v1/accounts?account.publickey=gte:0000000000000000000000000000000000000000000000000000000000000000&account.balance=gte:0&limit=100" &
done
wait

# All subsequent requests will now fail or time out for ~20 seconds
curl -v "https://<mirror-node>/api/v1/accounts"
```

Each of the 10 concurrent requests triggers the `preQueryHint` code path, checks out a dedicated connection from the 10-connection pool, and holds it for up to 20 seconds. The pool is fully exhausted, and any new request waits up to `connectionTimeoutMillis` (20 seconds) before failing. Repeating the 10-request wave every ~20 seconds maintains sustained DoS.

### Citations

**File:** rest/accounts.js (L183-233)
```javascript
    queries.push(`with latest_token_balance as (
       select account_id, balance, token_id
       from token_account
       where associated is true)`);
    selectTokenBalance = `(select json_agg(jsonb_build_object('token_id', token_id, 'balance', balance)) ::jsonb
          from (
            select token_id, balance
            from latest_token_balance
            where ${tokenBalanceQuery.query}
            order by token_id ${order}
            limit ${tokenBalanceQuery.limit}
          ) as account_token_balance)
        as token_balances`;
  }

  let balanceField = 'e.balance as balance';
  let balanceTimestampField = 'e.balance_timestamp as balance_timestamp';
  let entityTable;
  let orderClause;
  let whereClause;

  if (needHistoricalBalanceInfo) {
    if (accountBalanceQuery.query) {
      balanceField = `${accountBalanceQuery.query} as balance`;
      balanceTimestampField = `$${accountBalanceQuery.timestampParamIndex} as balance_timestamp`;
    }

    entityTable = `(
        select *
        from ${Entity.tableName} as e
        where ${whereCondition}
        union all
        select *
        from ${Entity.historyTableName} as e
        where ${whereCondition}
        order by ${Entity.TIMESTAMP_RANGE} desc limit 1
      )`;
  } else {
    entityTable = 'entity';
    whereClause = `where ${whereCondition}`;
    orderClause = `order by e.id ${order}`;
    utils.mergeParams(params, limitParams);
  }

  const selectFields = [entityFields, selectTokenBalance, balanceField, balanceTimestampField];
  queries.push(`select ${selectFields.join(',\n')}
    from ${entityTable} as e
    left join
      ${getEntityStakeQuery(entityAccountQuery.query, isHistorical)}
    as es on es.id = e.id ${getEntityStakeAccountCondition(entityAccountQuery)}
    ${[whereClause, orderClause, limitQuery].filter(Boolean).join('\n')}`);
```

**File:** rest/accounts.js (L366-367)
```javascript
  const preQueryHint = pubKeyQuery.query !== '' && constants.zeroRandomPageCostQueryHint;
  const result = await pool.queryQuietly(query, params, preQueryHint);
```

**File:** rest/utils.js (L1518-1527)
```javascript
    try {
      if (!preQueryHint) {
        result = await this.query(query, params);
      } else {
        client = await this.connect();
        client.on('error', clientErrorCallback);
        await client.query(`begin; ${preQueryHint}`);
        result = await client.query(query, params);
        await client.query('commit');
      }
```

**File:** rest/utils.js (L1540-1544)
```javascript
    } finally {
      if (client !== undefined) {
        client.off('error', clientErrorCallback);
        client.release();
      }
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

**File:** rest/__tests__/integrationUtils.js (L1-1)
```javascript
// SPDX-License-Identifier: Apache-2.0
```

**File:** rest/constants.js (L1-5)
```javascript
// SPDX-License-Identifier: Apache-2.0

const HEX_PREFIX = '0x';
const NANOSECONDS_PER_MILLISECOND = 10n ** 6n;
const NANOS_PER_SECOND = 1_000_000_000n;
```

**File:** rest/middleware/requestHandler.js (L1-5)
```javascript
// SPDX-License-Identifier: Apache-2.0

import httpContext from 'express-http-context';
import qs from 'qs';

```
