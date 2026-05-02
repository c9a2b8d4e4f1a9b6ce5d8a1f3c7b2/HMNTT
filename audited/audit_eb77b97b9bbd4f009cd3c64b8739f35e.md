### Title
Unbounded SQL OR Expansion via `inner_transactions` Array in `getTransactionsByIdOrHash()` Causes DB Resource Exhaustion (DoS)

### Summary
When `getTransactionsByIdOrHash()` processes a transaction ID belonging to an ATOMIC_BATCH transaction, it reads the `inner_transactions` array from the database result and passes it without any size cap to `getTransactionsByTransactionIdsSql()`. That function generates one parameterized OR condition per inner-transaction pair, producing an arbitrarily large SQL `WHERE` clause. Any unauthenticated user who knows the transaction ID of a large batch transaction can repeatedly trigger this path, exhausting DB CPU and connection-pool resources.

### Finding Description

**Exact code path:**

In `rest/transactions.js`, `getTransactionsByIdOrHash()` (lines 944–958):

```js
const innerTransactions = rows
  .map((row) => row.inner_transactions)
  .filter((innerTransactions) => innerTransactions)
  .flat();                                          // no length cap

if (!isTransactionHash && innerTransactions.length > 0) {
  const {query: innerTransactionQuery, params} = getTransactionsByTransactionIdsSql(
    innerTransactions,   // ← passed verbatim, no limit
    filters,
    Transaction.VALID_START_NS
  );
  const {rows: innerTransactionRows} = await pool.queryQuietly(innerTransactionQuery, params);
  ...
}
``` [1](#0-0) 

In `getTransactionsByTransactionIdsSql()` (lines 840–883), for every pair in `transactionKeys` the function appends one OR clause:

```js
for (let index = 0; index < transactionKeys.length; index += 2) {
  ...
  idConditions.push(`(${Transaction.PAYER_ACCOUNT_ID} = $${paramIndex} and
                       ${timestampField} = $${++paramIndex})`);
  ...
}
const mainConditions = [...commonConditions, `(${idConditions.join(' or ')})`, ...filterConditions].join(' and ');
``` [2](#0-1) 

**Root cause:** The `inner_transactions` column is a `bigint[]` with no size constraint in the schema:

```sql
alter table if exists transaction
  add column if not exists inner_transactions bigint[] default null;
``` [3](#0-2) 

The Java domain model stores pairs `[payer_account_id, valid_start_ns]` per inner transaction with no enforced upper bound: [4](#0-3) 

**Failed assumption:** The code assumes `inner_transactions` will always be small enough that expanding it into an OR clause is safe. No guard exists between reading the array from the DB and passing it to the SQL builder.

**Exploit flow:**
1. Attacker submits an ATOMIC_BATCH transaction to the Hedera network containing the maximum allowed number of inner transactions (paying the required fees once).
2. The mirror node importer ingests the batch and stores the full `inner_transactions` bigint array in the `transaction` table.
3. Attacker sends repeated `GET /api/v1/transactions/<batch-tx-id>` requests (no authentication required).
4. Each request triggers two DB queries: the initial lookup (cheap) and then the inner-transaction query with N OR conditions (expensive).
5. With N inner transactions, the generated SQL WHERE clause contains N `(payer_account_id = $i and valid_start_ns = $j)` terms joined by `OR`, plus three correlated subqueries (crypto_transfer, token_transfer, assessed_custom_fee) each also filtered by the same expanded condition set.

### Impact Explanation

Each request forces PostgreSQL to evaluate an arbitrarily wide OR predicate across the `transaction` table and three correlated subquery tables. With a large enough batch, each query consumes significant CPU and memory for the duration of the `statementTimeout` (default 20 s): [5](#0-4) 

The DB connection pool is capped at 10 connections by default (`maxConnections: 10`). A small number of concurrent requests against a large batch transaction ID can saturate the pool, causing all other API endpoints to queue or time out. This is a full denial-of-service against the mirror node REST API.

### Likelihood Explanation

- **No privilege required:** The REST endpoint is public and unauthenticated.
- **One-time setup cost:** The attacker pays Hedera network fees once to submit the large batch transaction. After ingestion, the attack is free to repeat indefinitely.
- **Repeatability:** The same transaction ID can be queried in a tight loop from multiple clients. The `statementTimeout` of 20 s means each request holds a DB connection for up to 20 s, making pool exhaustion easy with just a handful of concurrent attackers.
- **No rate limiting on the REST API:** The REST API has no per-IP or per-endpoint rate limiting configured for the `/transactions/{id}` path.

### Recommendation

1. **Cap `inner_transactions` before SQL expansion:** Before calling `getTransactionsByTransactionIdsSql()`, enforce a hard limit on `innerTransactions.length` (e.g., reject or truncate if it exceeds a configurable maximum such as 50 pairs / 100 elements).
2. **Use `= ANY($1)` with array parameters** instead of expanding N OR conditions, so the query plan is stable regardless of batch size.
3. **Add a DB-level constraint** on the `inner_transactions` column length, or enforce it in the importer's `addInnerTransaction()` method.
4. **Apply per-endpoint rate limiting** to `/api/v1/transactions/:transactionIdOrHash`.

### Proof of Concept

```
# Step 1: Submit an ATOMIC_BATCH transaction with 100 inner transactions to Hedera mainnet/testnet.
# The resulting transaction ID is, e.g., 0.0.1234-1700000000-000000000

# Step 2: Confirm ingestion
curl https://<mirror-node>/api/v1/transactions/0.0.1234-1700000000-000000000

# Step 3: Flood the endpoint (10 concurrent, sustained)
for i in $(seq 1 10); do
  while true; do
    curl -s https://<mirror-node>/api/v1/transactions/0.0.1234-1700000000-000000000 -o /dev/null &
  done
done

# Expected result:
# - DB connection pool saturated (10/10 connections held for up to 20s each)
# - All other REST API endpoints return 503 / timeout
# - PostgreSQL CPU spikes to 100% on the replica
```

The generated SQL for 100 inner transactions will contain a WHERE clause with 100 OR terms, each evaluated against the full `transaction` table plus three correlated subqueries, repeated on every request.

### Citations

**File:** rest/transactions.js (L840-883)
```javascript
  for (let index = 0; index < transactionKeys.length; index += 2) {
    let paramIndex = params.length;
    const payer = transactionKeys[index];
    const timestamp = BigInt(transactionKeys[index + 1]);

    if (payer) {
      payerAccountParams.push(`$${++paramIndex}`);
      idConditions.push(`(${Transaction.PAYER_ACCOUNT_ID} = $${paramIndex} and 
                               ${timestampField} = $${++paramIndex})`);
      params.push(payer);
    } else if (timestampField === Transaction.VALID_START_NS) {
      throw new InvalidArgumentError('payer is required when timestamp is valid_start_ns');
    } else {
      idConditions.push(`${timestampField} = $${++paramIndex}`);
    }
    params.push(timestamp);

    if (timestamp < minTimestamp) {
      minTimestamp = timestamp;
    }
    if (timestamp > maxTimestamp) {
      maxTimestamp = timestamp;
    }
  }

  const maxConsensusTimestamp =
    timestampField === Transaction.CONSENSUS_TIMESTAMP
      ? transactionKeys[transactionKeys.length - 1]
      : maxTimestamp + maxTransactionConsensusTimestampRangeNs;
  const commonConditions = [
    `${Transaction.CONSENSUS_TIMESTAMP} >= $${params.length + 1}`,
    `${Transaction.CONSENSUS_TIMESTAMP} <= $${params.length + 2}`,
  ];
  params.lowerConsensusTimestampIndex = params.length;
  params.push(
    timestampField === Transaction.VALID_START_NS
      ? minTimestamp - config.query.maxValidStartTimestampDriftNs
      : minTimestamp
  );
  params.upperConsensusTimestampIndex = params.length;
  params.push(maxConsensusTimestamp);

  const {conditions: filterConditions, scheduled} = getTransactionByIdQueryParamConditions(filters, params);
  const mainConditions = [...commonConditions, `(${idConditions.join(' or ')})`, ...filterConditions].join(' and ');
```

**File:** rest/transactions.js (L944-958)
```javascript
  const innerTransactions = rows
    .map((row) => row.inner_transactions)
    .filter((innerTransactions) => innerTransactions)
    .flat();

  if (!isTransactionHash && innerTransactions.length > 0) {
    const {query: innerTransactionQuery, params} = getTransactionsByTransactionIdsSql(
      innerTransactions,
      filters,
      Transaction.VALID_START_NS
    );
    const {rows: innerTransactionRows} = await pool.queryQuietly(innerTransactionQuery, params);

    rows.push(...innerTransactionRows);
  }
```

**File:** importer/src/main/resources/db/migration/v1/V1.105.1__batch_transactions.sql (L1-3)
```sql
alter table if exists transaction
    add column if not exists batch_key          bytea      default null,
    add column if not exists inner_transactions bigint[] default null;
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/Transaction.java (L142-153)
```java
    public void addInnerTransaction(Transaction transaction) {
        if (this.type != TransactionType.ATOMIC_BATCH.getProtoId()) {
            throw new IllegalStateException("Inner transactions can only be added to atomic batch transaction");
        }

        if (innerTransactions == null) {
            innerTransactions = new ArrayList<>();
        }

        innerTransactions.add(transaction.getPayerAccountId().getId());
        innerTransactions.add(transaction.getValidStartNs());
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
