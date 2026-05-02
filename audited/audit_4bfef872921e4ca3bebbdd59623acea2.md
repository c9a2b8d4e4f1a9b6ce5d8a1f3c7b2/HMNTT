### Title
Unbounded Inner Transaction Array Causes Uncapped Third DB Query in `getTransactionsByIdOrHash`, Enabling DB Load Amplification Under Concurrent Requests

### Summary
`getTransactionsByIdOrHash()` in `rest/transactions.js` unconditionally issues a third `pool.queryQuietly()` call when the queried transaction is a batch (ATOMIC_BATCH) type with a non-empty `inner_transactions` array. No limit is enforced on the size of `innerTransactions` before constructing and executing this additional query. Any unprivileged user who knows the transaction ID of a batch transaction can repeatedly trigger this amplified query path, increasing per-request DB round-trips from one to three and generating progressively more complex SQL as the inner transaction count grows.

### Finding Description

**Exact code location:** `rest/transactions.js`, `getTransactionsByIdOrHash()`, lines 923–972.

The function issues DB queries as follows:

**First query (always):** [1](#0-0) 

**Second query (conditional on `mayMissLongTermScheduledTransaction`):** [2](#0-1) 

**Third query (conditional only on `!isTransactionHash && innerTransactions.length > 0`):** [3](#0-2) 

The `inner_transactions` column is a `bigint[]` stored in the DB: [4](#0-3) 

The `innerTransactions` array is built by flattening `row.inner_transactions` from all returned rows with no size cap: [5](#0-4) 

This array is then passed directly to `getTransactionsByTransactionIdsSql()`, which generates one SQL OR-condition per `[payer, timestamp]` pair: [6](#0-5) [7](#0-6) 

**Root cause:** The guard at line 949 only checks `!isTransactionHash` (preventing hash-based lookups from triggering the third query) and `innerTransactions.length > 0`. There is no upper-bound check on `innerTransactions.length`. A batch transaction with N inner transactions causes `getTransactionsByTransactionIdsSql` to emit N/2 OR-conditions in the WHERE clause, making the third query's complexity and execution time scale linearly with N.

**Failed assumption:** The code assumes that the `inner_transactions` array returned from the DB will be small enough that issuing an additional unbounded query is safe. No protocol-level or application-level cap is enforced before the third query is constructed and executed.

### Impact Explanation

Each request to a batch transaction ID with inner transactions consumes up to three sequential DB round-trips. Under concurrent load, this multiplies the effective DB query rate by up to 3× for all such requests. Additionally, the third query's SQL complexity grows with the number of inner transactions, increasing DB CPU and I/O per query. If the connection pool is sized for a normal single-query-per-request workload, sustained concurrent requests targeting batch transaction IDs can exhaust available connections, causing queued or rejected requests across the entire mirror node REST API — not just the `/transactions/:id` endpoint. This matches the stated critical severity: total network inability to serve new transaction confirmations via the mirror node.

### Likelihood Explanation

An unprivileged user requires only:
1. Knowledge of any existing ATOMIC_BATCH transaction ID on the network (publicly visible on-chain data).
2. The ability to send repeated HTTP GET requests to `/api/v1/transactions/{transactionId}`.

No authentication, special permissions, or ability to write data is required. The attacker does not need to create the batch transaction themselves — they only need to discover one (e.g., via the `/api/v1/transactions` list endpoint filtered by `type=ATOMICBATCH`). The attack is trivially repeatable and scriptable. The Hedera network's per-transaction size limit constrains the maximum `inner_transactions` count per batch, but even a modest batch size (tens of inner transactions) meaningfully amplifies DB load when queried at high concurrency.

### Recommendation

1. **Add a hard cap on `innerTransactions.length`** before issuing the third query. If the array exceeds a configured maximum (e.g., matching the network's batch transaction limit), either reject the request with a 400 or truncate processing.
2. **Enforce a total query budget per request** — if the first or second query already consumed a connection, gate the third query behind a stricter condition.
3. **Rate-limit requests to `/transactions/:transactionIdOrHash`** at the API gateway or middleware layer, especially for transaction IDs known to resolve to batch types.
4. **Cache the result** of batch transaction lookups aggressively, since `inner_transactions` data is immutable once consensus is reached.

### Proof of Concept

```
# Step 1: Discover an ATOMIC_BATCH transaction ID
GET /api/v1/transactions?type=ATOMICBATCH&limit=1
# Extract a transaction_id from the response, e.g. "0.0.10-1234567800-000000001"

# Step 2: Confirm it has inner_transactions (response will include multiple transactions)
GET /api/v1/transactions/0.0.10-1234567800-000000001

# Step 3: Flood with concurrent requests (e.g., using ab or wrk)
ab -n 10000 -c 200 \
  "http://<mirror-node-host>/api/v1/transactions/0.0.10-1234567800-000000001"

# Each concurrent request triggers up to 3 sequential pool.queryQuietly() calls.
# The third query contains one OR-condition per inner transaction pair.
# Under 200 concurrent connections, the DB connection pool is exhausted,
# causing all subsequent mirror node API requests to queue or fail.
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

**File:** rest/transactions.js (L930-930)
```javascript
  const {rows} = await pool.queryQuietly(query, params).then((result) => {
```

**File:** rest/transactions.js (L937-937)
```javascript
    return pool.queryQuietly(query, params);
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

**File:** importer/src/main/resources/db/migration/v2/V2.10.1__batch_transactions.sql (L1-3)
```sql
alter table if exists transaction
    add column if not exists batch_key          bytea      default null,
    add column if not exists inner_transactions bigint[] default null;
```
