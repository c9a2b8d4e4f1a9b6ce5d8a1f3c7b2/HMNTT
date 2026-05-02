### Title
Missing Account Filter Enforcement Allows Full-Table Scan via `credit_type=debit` Without `account.id`

### Summary
An unprivileged user can supply `credit_type=debit` (or `credit`) without an `account.id` parameter to the `/api/v1/transactions` endpoint. This causes `getTransactionTimestampsQuery()` to execute a FULL OUTER JOIN between `crypto_transfer` and `token_transfer` subqueries that carry no account predicate — only a timestamp range and an `amount < 0` condition — resulting in a broad, expensive table scan that can be repeatedly triggered to degrade database performance for all users.

### Finding Description

**Code path:**

In `rest/transactions.js`, `extractSqlFromTransactionsRequest()` builds `creditDebitQuery` independently of `accountQuery`: [1](#0-0) 

When `credit_type=debit` is supplied without `account.id`, `creditDebitQuery` becomes `'ctl.amount < 0'` and `accountQuery` remains `''`.

`getTransactionTimestampsQuery()` then evaluates: [2](#0-1) 

Because `creditDebitQuery` is truthy, execution enters the credit/debit branch. Two subqueries are built via `getTransferDistinctTimestampsQuery()`: [3](#0-2) 

Inside `getTransferDistinctTimestampsQuery()`, the WHERE clause is assembled from the provided arguments: [4](#0-3) 

With `accountQuery = ''`, the WHERE clause reduces to only `transferTimestampQuery` (the bounded timestamp range) and `creditDebitQuery` (`ctl.amount < 0`). No account column is filtered.

These two unfiltered subqueries are then combined in a FULL OUTER JOIN: [5](#0-4) 

**Root cause:** There is no validation gate that requires `account.id` to be present when `credit_type` is supplied. The branching condition at line 555 treats a lone `creditDebitQuery` as sufficient to enter the expensive FULL OUTER JOIN path.

### Impact Explanation

Without an account predicate, both the `crypto_transfer` and `token_transfer` subqueries perform sequential or index-range scans over all rows matching `amount < 0` within the timestamp window. On a production mirror node with millions of transfers, this is a heavy read operation. The FULL OUTER JOIN then merges two large intermediate result sets. Because the endpoint is public and unauthenticated, an attacker can issue this request in a tight loop, saturating database I/O and CPU, degrading response times for all legitimate users. The impact is service degradation (griefing), not data exfiltration or fund loss.

### Likelihood Explanation

The attack requires zero privileges — it is a plain HTTP GET request to a public REST endpoint. The parameter `type=debit` (mapped to `credit_type`) is documented in the API. The request is trivially repeatable with `curl` or any HTTP client. No special knowledge of the system internals is needed beyond reading the public API docs.

### Recommendation

1. **Require `account.id` when `credit_type` is used.** In `extractSqlFromTransactionsRequest()` or in `getTransactions()`, reject (HTTP 400) any request that sets `credit_type` without at least one `account.id` filter.
2. **Alternatively**, if `credit_type` without `account.id` is an intentional feature, enforce a tighter maximum timestamp range for that code path (narrower than `maxTransactionConsensusTimestampRangeNs`) to bound the scan size.
3. Add a rate-limit or query-cost guard specifically for the FULL OUTER JOIN path in `getTransactionTimestampsQuery()`.

### Proof of Concept

```
# No account.id supplied — only credit_type=debit
GET /api/v1/transactions?type=debit

# Equivalent with explicit timestamp range to maximise scan
GET /api/v1/transactions?type=debit&timestamp=gte:0&timestamp=lte:9999999999.999999999
```

**Step-by-step:**
1. Send the request above to a running mirror-node REST service.
2. `buildAndValidateFilters` accepts the request (no account.id requirement enforced).
3. `extractSqlFromTransactionsRequest` sets `creditDebitQuery = 'ctl.amount < 0'`, `accountQuery = ''`.
4. `getTransactionTimestampsQuery` enters the `if (creditDebitQuery || accountQuery)` branch at line 555.
5. Both `getTransferDistinctTimestampsQuery` calls produce subqueries with no account predicate.
6. The FULL OUTER JOIN is executed against the full `crypto_transfer` and `token_transfer` tables, bounded only by the timestamp range.
7. Repeat in a loop to exhaust database resources.

### Citations

**File:** rest/transactions.js (L343-349)
```javascript
  const whereClause = buildWhereClause(
    accountQuery,
    transferTimestampQuery,
    resultTypeQuery,
    transactionTypeQuery,
    creditDebitQuery
  );
```

**File:** rest/transactions.js (L421-424)
```javascript
  if (lastCreditDebitValue) {
    const operator = lastCreditDebitValue.toLowerCase() === constants.cryptoTransferType.CREDIT ? '>' : '<';
    creditDebitQuery = `ctl.amount ${operator} 0`;
  }
```

**File:** rest/transactions.js (L555-555)
```javascript
  if (creditDebitQuery || accountQuery) {
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

**File:** rest/transactions.js (L583-590)
```javascript
      return `
          select coalesce(ctl.consensus_timestamp, ttl.consensus_timestamp) as consensus_timestamp,
                 coalesce(ctl.payer_account_id, ttl.payer_account_id)       as payer_account_id
          from (${cryptoTransferQuery}) as ctl
                   full outer join (${tokenTransferQuery}) as ttl
                                   on ctl.consensus_timestamp = ttl.consensus_timestamp
          order by consensus_timestamp ${order}
              ${limitQuery}`;
```
