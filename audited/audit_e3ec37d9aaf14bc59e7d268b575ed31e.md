### Title
Unbounded Inner Transaction Expansion DoS in `getTransactionsByIdOrHash`

### Summary
`getTransactionsByIdOrHash` in `rest/transactions.js` fetches all inner transactions from a batch transaction's `inner_transactions` array without any count limit, then issues a second unbounded SQL query and a third unbounded staking-reward query proportional to the result set. Because the endpoint has no response caching, an attacker can repeatedly query a single batch transaction ID to amplify database and CPU load with no per-request cost.

### Finding Description

**Exact code path:**

`rest/transactions.js` lines 944–960 — after the initial transaction lookup, the code collects every `inner_transactions` entry from the returned rows and passes the entire array, without any size cap, to `getTransactionsByTransactionIdsSql`:

```js
// lines 944-958
const innerTransactions = rows
  .map((row) => row.inner_transactions)
  .filter((innerTransactions) => innerTransactions)
  .flat();                                          // no length check

if (!isTransactionHash && innerTransactions.length > 0) {
  const {query: innerTransactionQuery, params} = getTransactionsByTransactionIdsSql(
    innerTransactions,          // N pairs → N OR-conditions, 2N params
    filters,
    Transaction.VALID_START_NS
  );
  const {rows: innerTransactionRows} = await pool.queryQuietly(innerTransactionQuery, params);
  rows.push(...innerTransactionRows);               // unbounded append
}

const transactions = await formatTransactionRows(rows);  // line 960
```

`formatTransactionRows` (line 191–225) immediately calls `createStakingRewardTransferList(rows)` (line 192), which calls `getStakingRewardTransferList` (lines 265–282). That function builds a `WHERE consensus_timestamp IN ($1, …, $N)` query with one parameter per row — again with no cap:

```js
// lines 270-278
const positions = range(1, stakingRewardTimestamps.length + 1).map((position) => `$${position}`);
const query = `… where ${StakingRewardTransfer.CONSENSUS_TIMESTAMP} in (${positions}) …`;
```

**Root cause:** The failed assumption is that `inner_transactions` will always be small. There is no guard of the form `if (innerTransactions.length > MAX) throw …` anywhere in the path.

**Why caching does not help:** The `Cache` object is used only inside `doGetTransactions` (line 705). `getTransactionsByIdOrHash` (line 923) never calls `cache.get()`, so every HTTP request re-executes all three database round-trips.

**Exploit flow:**
1. Attacker submits (or locates an existing) `ATOMIC_BATCH` transaction on the Hedera network containing the maximum number of inner transactions. The `inner_transactions` column stores pairs `[payer_account_id, valid_start_ns]` as `bigint[]`; each pair is 16 bytes. Within Hedera's ~6 KB transaction body limit, this allows on the order of tens to a few hundred inner transactions.
2. The mirror node importer ingests the batch and stores the full `inner_transactions` array in the `transaction` table with no truncation.
3. Attacker sends a high-rate stream of `GET /api/v1/transactions/<batchTxId>` requests. Each request triggers:
   - Query 1: fetch the batch transaction row.
   - Query 2: `getTransactionsByTransactionIdsSql` with N OR-conditions and 2N+2 parameters.
   - Query 3: staking-reward `IN (…)` query with up to N timestamps.
   - In-process: `formatTransactionRows` iterates all N+1 rows, calling multiple list-building helpers per row.
4. Because there is no caching and no rate-limit specific to this endpoint, each concurrent request independently executes the full chain.

### Impact Explanation
Each request to a large batch transaction ID causes at least three database queries whose complexity scales linearly with the number of inner transactions, plus proportional in-process CPU work. Sustained concurrent requests can exhaust the database connection pool, spike CPU on the REST service, and degrade or deny service to all other API consumers. This is a denial-of-service amplification: the attacker's cost is one HTTP request per iteration; the server's cost is O(N) database work per request.

### Likelihood Explanation
The attack requires a batch transaction to exist on the network. An attacker can submit one themselves (costs HBAR, a real but low barrier on testnet/previewnet, and feasible on mainnet for a motivated attacker). Alternatively, any large batch transaction submitted by a legitimate user can be used as the trigger indefinitely at zero additional cost to the attacker. The endpoint is publicly accessible with no authentication. The attack is trivially repeatable with a simple HTTP loop.

### Recommendation
1. **Add a hard cap on `innerTransactions.length`** before calling `getTransactionsByTransactionIdsSql`. Reject or truncate if the count exceeds a reasonable maximum (e.g., 50 or the network's documented batch limit).
2. **Cache the result of `getTransactionsByIdOrHash`** using the same `Cache` mechanism already used in `doGetTransactions`, keyed on the transaction ID string.
3. **Add a limit clause** to the inner-transaction SQL query so the database cannot return more rows than the cap.
4. **Cap the staking-reward IN-list** in `getStakingRewardTransferList` to prevent unbounded parameter arrays.

### Proof of Concept
```
# 1. Submit an ATOMIC_BATCH transaction to Hedera testnet with the maximum
#    number of inner transactions (e.g., 50 CryptoTransfer inners).
#    Record the resulting transaction ID, e.g.: 0.0.1234-1700000000-000000000

# 2. Flood the mirror node REST API:
while true; do
  curl -s "https://<mirror-node>/api/v1/transactions/0.0.1234-1700000000-000000000" &
done

# Each concurrent request independently executes:
#   - 1 primary transaction query
#   - 1 inner-transaction query with 50 OR-conditions / 102 parameters
#   - 1 staking-reward IN query with up to 50 timestamps
# No caching absorbs any of these requests.
# Observable result: database CPU/connection saturation, elevated REST latency,
# eventual 503/timeout responses for all API consumers.
```