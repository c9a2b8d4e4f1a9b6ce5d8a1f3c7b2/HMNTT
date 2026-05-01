### Title
Unbounded `inner_transactions` Expansion Causes Amplified DB and Memory Load in `getTransactionsByIdOrHash()`

### Summary
When `getTransactionsByIdOrHash()` resolves a transaction ID to an ATOMIC_BATCH transaction, it unconditionally collects the entire `inner_transactions` array from the DB row and issues a second unbounded DB query for all inner transaction keys — with no cap on array size, no caching, and no rate-limiting in the handler. Any unauthenticated caller who can identify a batch transaction ID can repeatedly trigger this amplification path, exhausting DB connections and node memory.

### Finding Description

**Exact code path** — `rest/transactions.js`, lines 944–958:

```js
const innerTransactions = rows
  .map((row) => row.inner_transactions)
  .filter((innerTransactions) => innerTransactions)
  .flat();                                          // ← no length cap

if (!isTransactionHash && innerTransactions.length > 0) {
  const {query: innerTransactionQuery, params} = getTransactionsByTransactionIdsSql(
    innerTransactions,          // ← full unbounded array passed in
    filters,
    Transaction.VALID_START_NS
  );
  const {rows: innerTransactionRows} = await pool.queryQuietly(innerTransactionQuery, params);
  rows.push(...innerTransactionRows);               // ← all results merged into memory
}

const transactions = await formatTransactionRows(rows);  // ← processes combined set
``` [1](#0-0) 

**Root cause — `getTransactionsByTransactionIdsSql` with N pairs generates N OR-conditions:**

```js
for (let index = 0; index < transactionKeys.length; index += 2) {
  idConditions.push(`(${Transaction.PAYER_ACCOUNT_ID} = $${paramIndex} and
                       ${timestampField} = $${++paramIndex})`);
  ...
}
// mainConditions = "... AND (cond1 OR cond2 OR ... OR condN)"
``` [2](#0-1) 

For N inner transactions the generated SQL has N OR-clauses, N×2 bound parameters, and the subquery `IN (...)` list also grows linearly. The combined result set is then held in memory and iterated by `formatTransactionRows`.

**Failed assumption**: The code assumes `inner_transactions` is small. The DB column is `bigint[]` with no schema-level size constraint: [3](#0-2) 

**No caching**: `doGetTransactions` uses `cache.get()` but `getTransactionsByIdOrHash` calls `pool.queryQuietly` directly — every request re-executes both queries. [4](#0-3) 

### Impact Explanation
Each HTTP request to `GET /api/v1/transactions/{batchTxId}` against a batch transaction with N inner transactions causes:
1. One DB query for the batch transaction row.
2. One DB query with N OR-conditions and N×2 parameters for all inner transactions.
3. Allocation of all N+1 result rows in Node.js heap.
4. Full `formatTransactionRows` pass over the combined set (including staking-reward sub-queries per row).

With concurrent requests from multiple attackers (or a single attacker with parallel connections), DB connection pool slots are held for the duration of the large query, heap pressure grows proportionally, and the event loop stalls on the synchronous `rows.push(...innerTransactionRows)` spread. This can degrade or crash mirror-node REST instances across a horizontally-scaled deployment, meeting the ≥30% node impact threshold.

### Likelihood Explanation
**Precondition**: A batch transaction with many inner transactions must exist in the mirror node DB. This can be achieved by:
- Submitting an ATOMIC_BATCH transaction to the Hedera network (costs HBAR fees, but is a one-time cost).
- Or simply discovering an existing high-inner-count batch transaction via the public `/transactions` list endpoint — no fees required.

**Trigger**: Once the transaction ID is known, any unauthenticated caller can issue repeated `GET /api/v1/transactions/{id}` requests. No credentials, no special headers, no privileged access required. The endpoint is publicly reachable.

**Repeatability**: The attack is fully repeatable. Because there is no caching on this handler, every request re-executes the full amplified query chain. A single attacker with a script loop is sufficient; a botnet is not required.

### Recommendation
1. **Cap `innerTransactions` before the second query**: add a hard limit (e.g., matching the Hedera protocol batch limit) and return an error or truncate if exceeded.
2. **Cache the result**: apply the same `cache.get()` pattern used in `doGetTransactions` so repeated lookups for the same batch transaction ID are served from cache.
3. **Apply a DB statement timeout** specific to this handler or enforce a maximum parameter count in `getTransactionsByTransactionIdsSql`.
4. **Rate-limit** the `/transactions/:id` endpoint at the API-gateway or middleware layer.

### Proof of Concept
```
# Step 1: Submit (or locate) an ATOMIC_BATCH transaction with many inner transactions.
# The transaction ID is, e.g., 0.0.1234-1700000000-000000000

# Step 2: Flood the mirror node REST API (no auth required):
while true; do
  curl -s "https://<mirror-node>/api/v1/transactions/0.0.1234-1700000000-000000000" &
done

# Each concurrent request triggers:
#   - pool.queryQuietly(batchTxQuery, ...)
#   - pool.queryQuietly(innerTxQuery with N OR-conditions, ...)
#   - formatTransactionRows on N+1 rows
# DB connection pool exhausts; heap grows; node processes degrade.
```

### Citations

**File:** rest/transactions.js (L840-863)
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
```

**File:** rest/transactions.js (L923-972)
```javascript
const getTransactionsByIdOrHash = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedSingleTransactionParameters);
  const {query, params, scheduled, isTransactionHash} = await extractSqlFromTransactionsByIdOrHashRequest(
    req.params.transactionIdOrHash,
    filters
  );

  const {rows} = await pool.queryQuietly(query, params).then((result) => {
    if (!mayMissLongTermScheduledTransaction(isTransactionHash, scheduled, result.rows)) {
      return result;
    }

    params[params.upperConsensusTimestampIndex] =
      params[params.lowerConsensusTimestampIndex] + maxScheduledTransactionConsensusTimestampRangeNs;
    return pool.queryQuietly(query, params);
  });

  if (rows.length === 0) {
    throw new NotFoundError();
  }

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

  const transactions = await formatTransactionRows(rows);

  res.locals[constants.responseHeadersLabel] = getTransactionsByIdOrHashCacheControlHeader(
    isTransactionHash,
    scheduled !== undefined,
    rows
  );

  logger.debug(`getTransactionsByIdOrHash returning ${transactions.length} entries`);
  res.locals[constants.responseDataLabel] = {
    transactions,
  };
};
```

**File:** importer/src/main/resources/db/migration/v2/V2.10.1__batch_transactions.sql (L1-3)
```sql
alter table if exists transaction
    add column if not exists batch_key          bytea      default null,
    add column if not exists inner_transactions bigint[] default null;
```
