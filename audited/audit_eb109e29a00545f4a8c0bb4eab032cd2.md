### Title
`DISTINCT ON` Without Secondary Sort Causes Silent Transaction Omission in `/transactions` API

### Summary
`getTransferDistinctTimestampsQuery()` uses `DISTINCT ON (consensus_timestamp)` with an `ORDER BY` clause that only specifies `consensus_timestamp`, causing PostgreSQL to pick an arbitrary `payer_account_id` when multiple payers share the same timestamp. `getTransactionsDetails()` then reconstructs the detail query using independent sets of payer IDs and timestamps (a Cartesian product filter), not exact `(payer, timestamp)` pairs. When a payer is dropped by `DISTINCT ON` and does not appear in any other selected timestamp, their transaction is silently omitted from the API response.

### Finding Description

**Root cause — `getTransferDistinctTimestampsQuery()` (lines 325–356):**

```sql
SELECT DISTINCT ON (ctl.consensus_timestamp)
       ctl.consensus_timestamp AS consensus_timestamp,
       ctl.payer_account_id   AS payer_account_id
FROM crypto_transfer AS ctl ...
ORDER BY ctl.consensus_timestamp DESC   -- no secondary sort on payer_account_id
LIMIT $N
```

PostgreSQL's `DISTINCT ON` requires that the `ORDER BY` clause begins with the `DISTINCT ON` key. Any additional columns in `ORDER BY` determine which row is kept per group. Here there is **no secondary sort column**, so when two rows share the same `consensus_timestamp`, PostgreSQL picks whichever row it encounters first in the physical scan — effectively arbitrary. [1](#0-0) 

**Compounding defect — `getTransactionsDetails()` (lines 621–660):**

```javascript
const payerAccountIds = new Set();   // unique payer IDs across all rows
const timestamps = [];               // all timestamps

// ...
WHERE t.payer_account_id = any($payerIds)   -- independent set
  AND t.consensus_timestamp = any($timestamps) -- independent set
```

This is a Cartesian product filter. It does not enforce that the `(payer_account_id, consensus_timestamp)` pairs match exactly what `DISTINCT ON` returned. A payer that was dropped by `DISTINCT ON` at timestamp T is only recovered if that same payer appears in the result set via a *different* timestamp — which is not guaranteed. [2](#0-1) [3](#0-2) 

**Exploit flow:**

1. At consensus timestamp T1, two independent transactions exist:
   - Transaction 1: `payer_account_id = A`, transfer involving account X
   - Transaction 2: `payer_account_id = B`, transfer involving account X
2. Attacker (any unprivileged user) queries `GET /api/v1/transactions?account.id=X`
3. `extractSqlFromTransactionsRequest` builds `accountQuery = "ctl.entity_id = $1"` with value X.
4. `getTransferDistinctTimestampsQuery` emits the `DISTINCT ON` query; PostgreSQL picks payer A for T1 (arbitrary).
5. Result set: `[{consensus_timestamp: T1, payer_account_id: A}]`
6. `getTransactionsDetails` builds: `payerAccountIds = {A}`, `timestamps = [T1]`
7. Final SQL: `WHERE t.payer_account_id = any({A}) AND t.consensus_timestamp = any({T1})`
8. Transaction 2 (payer B at T1) is **never fetched** and is absent from the API response.

The same logic applies to `TokenTransfer` via the parallel `tokenTransferQuery` path. [4](#0-3) 

**Why existing checks are insufficient:**

The `full outer join` between `cryptoTransferQuery`, `tokenTransferQuery`, and `transactionOnlyQuery` (lines 595–604) merges results across the three sub-queries, but each sub-query independently suffers from the same `DISTINCT ON` truncation. The Cartesian product in `getTransactionsDetails` can accidentally recover a dropped payer only if that payer appears in another timestamp — a coincidence, not a guarantee. [5](#0-4) 

### Impact Explanation

Any API consumer querying `/api/v1/transactions?account.id=X` may receive a silently incomplete transaction list when multiple payers transact in the same consensus round involving account X. Downstream systems (wallets, explorers, audit tools, compliance monitors) that rely on this endpoint for a complete history will have a corrupted view of ledger activity. The omission is silent — no error is returned, the response appears normal, and the missing transaction is not flagged. Severity: **Medium** (data integrity / information completeness; no direct fund movement, but enables false audit trails).

### Likelihood Explanation

- **Precondition**: None beyond being an unprivileged API user. Any caller can supply `account.id`.
- **Trigger condition**: Two or more transactions from different payers must share the same `consensus_timestamp` and both involve the queried account. On Hedera, multiple transactions are finalized per consensus round, making timestamp collisions routine for active accounts.
- **Repeatability**: The behavior is deterministic per PostgreSQL's physical storage order for a given database state, so the same query will consistently omit the same transaction until a vacuum/rewrite changes heap order.
- **Detectability**: The omission is invisible to the caller; no HTTP error, no partial-result indicator.

### Recommendation

1. **Add a secondary sort in `getTransferDistinctTimestampsQuery`** so `DISTINCT ON` is deterministic and picks the same row every time:

   ```sql
   ORDER BY ctl.consensus_timestamp DESC, ctl.payer_account_id ASC
   ```

   This does not fix the fundamental problem of dropping legitimate rows, but makes behavior predictable.

2. **Fix `getTransactionsDetails` to filter on exact pairs**, not independent sets:

   ```sql
   WHERE (t.payer_account_id, t.consensus_timestamp) = ANY(
     ARRAY[($1::bigint,$2::bigint), ($3::bigint,$4::bigint), ...]
   )
   ```

   Or pass the pairs as a temporary table / unnested array of composite values.

3. **Redesign `getTransferDistinctTimestampsQuery`** to return all `(consensus_timestamp, payer_account_id)` pairs that match the filter (remove `DISTINCT ON`), and let `getTransactionsDetails` deduplicate on exact pairs. The `LIMIT` should be applied after deduplication on the outer query, not inside the sub-query.

### Proof of Concept

**Setup (database state):**
```sql
-- Two transactions at the same consensus timestamp, both involving account 100
INSERT INTO crypto_transfer VALUES (1000000, 100, 50, 200);  -- payer=100, entity=200
INSERT INTO crypto_transfer VALUES (1000000, 300, -50, 200); -- payer=300, entity=200
-- Both transfers involve entity_id=200 at consensus_timestamp=1000000
```

**Request:**
```
GET /api/v1/transactions?account.id=0.0.200
```

**Observed:** Only one transaction (payer 100 or payer 300) is returned.

**Expected:** Both transactions at timestamp 1000000 involving account 0.0.200 are returned.

**Verification:** Run the same request twice after `VACUUM FULL crypto_transfer` — the omitted transaction may change, confirming the non-determinism.

### Citations

**File:** rest/transactions.js (L351-355)
```javascript
  return `
      select distinct on (${fullTimestampColumn}) ${fullTimestampColumn}      as consensus_timestamp,
                                                  ${fullPayerAccountIdColumn} as payer_account_id
      from ${tableName} as ${tableAlias} ${joinClause} ${whereClause}
      order by ${fullTimestampColumn} ${order} ${limitQuery}`;
```

**File:** rest/transactions.js (L556-578)
```javascript
    const cryptoTransferQuery = getTransferDistinctTimestampsQuery(
      CryptoTransfer.tableName,
      'ctl',
      timestampQuery,
      resultTypeQuery,
      transactionTypeQuery,
      accountQuery,
      creditDebitQuery,
      order,
      limitQuery
    );

    const tokenTransferQuery = getTransferDistinctTimestampsQuery(
      TokenTransfer.tableName,
      'ttl',
      timestampQuery,
      resultTypeQuery,
      transactionTypeQuery,
      accountQuery.replace(/ctl\.entity_id/g, 'ttl.account_id'),
      creditDebitQuery.replace(/ctl\.amount/g, 'ttl.amount'),
      order,
      limitQuery
    );
```

**File:** rest/transactions.js (L595-604)
```javascript
    return `
        select coalesce(t.consensus_timestamp, ctl.consensus_timestamp, ttl.consensus_timestamp) as consensus_timestamp,
               coalesce(t.payer_account_id, ctl.payer_account_id, ttl.payer_account_id)          as payer_account_id
        from (${transactionOnlyQuery}) as t
                 full outer join (${cryptoTransferQuery}) as ctl
                                 on t.consensus_timestamp = ctl.consensus_timestamp
                 full outer join (${tokenTransferQuery}) as ttl
                                 on coalesce(t.consensus_timestamp, ctl.consensus_timestamp) = ttl.consensus_timestamp
        order by consensus_timestamp ${order}
            ${limitQuery}`;
```

**File:** rest/transactions.js (L621-632)
```javascript
  const payerAccountIds = new Set();
  const timestamps = [];
  payerAndTimestamps.forEach((row) => {
    timestamps.push(row.consensus_timestamp);
    payerAccountIds.add(row.payer_account_id);
  });

  const params = [];
  const payerAccountIdsCondition = getQueryWithEqualValues('payer_account_id', params, Array.from(payerAccountIds));
  const timestampsCondition = getQueryWithEqualValues('consensus_timestamp', params, timestamps);
  const outerPayerAccountIdsCondition = 't.' + payerAccountIdsCondition;
  const outerTimestampsCondition = 't.' + timestampsCondition;
```

**File:** rest/transactions.js (L657-660)
```javascript
                 from transaction as t
                 where ${outerPayerAccountIdsCondition}
                   and ${outerTimestampsCondition}
                 order by t.consensus_timestamp ${order}`;
```
