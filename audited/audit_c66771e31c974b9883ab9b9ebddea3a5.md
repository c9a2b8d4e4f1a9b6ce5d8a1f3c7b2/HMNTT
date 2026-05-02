### Title
Unauthenticated Amplified DB Load via Staking Reward Secondary Query in `formatTransactionRows()`

### Summary
Any unauthenticated user can craft timestamp-filtered requests to `/api/v1/transactions` that match transactions containing transfers from the staking reward account (entity ID 800), causing `formatTransactionRows()` to unconditionally invoke `createStakingRewardTransferList()`, which issues a secondary database query per cache-miss batch. With no rate limiting and the ability to rotate through many unique timestamps, an attacker can sustain a continuous stream of extra DB queries, amplifying backend load beyond what the primary query alone would produce.

### Finding Description

**Exact code path:**

`formatTransactionRows()` at [1](#0-0)  unconditionally calls `createStakingRewardTransferList(rows)` on every invocation, regardless of whether any staking reward transfers exist.

`createStakingRewardTransferList()` at [2](#0-1)  calls `getStakingRewardTimestamps()` to filter transactions whose `crypto_transfer_list` contains entity ID 800 (the staking reward account), then passes the resulting timestamps to `getStakingRewardTransferList()`.

`getStakingRewardTransferList()` at [3](#0-2)  issues a real secondary `pool.queryQuietly()` call against the `staking_reward_transfer` table whenever `stakingRewardTimestamps.length > 0`.

**Root cause:** The secondary query is gated only on whether the already-fetched transaction rows contain a transfer from entity 800. There is no per-user throttle, no global rate limit on this code path, and no pre-check before the query is issued.

**Cache interaction:** In `doGetTransactions`, the Redis cache at [4](#0-3)  stores formatted transaction rows keyed by `consensus_timestamp`. The `loader` (which calls `formatTransactionRows`) is only invoked for cache misses. However:
- An attacker rotating through many distinct timestamps (all matching staking reward transactions) keeps generating cache misses, each triggering one extra DB query.
- When Redis is unavailable (`!this.ready`), the cache falls back to calling `loader(keys)` directly at [5](#0-4) , meaning every request triggers the secondary query unconditionally.
- The `/transactions/:transactionIdOrHash` handler calls `formatTransactionRows(rows)` at [6](#0-5)  with **no caching at all**, so every request for a transaction with staking reward transfers issues the secondary query.

**No rate limiting exists** in the REST layer — the only match for `rateLimit` in `rest/**/*.js` is inside test utilities.

### Impact Explanation
Each attacker request that produces a cache miss on a staking-reward-bearing transaction causes one extra `SELECT` against the `staking_reward_transfer` table. At high request frequency with rotating timestamps, this doubles the effective DB query rate for those requests. Under sustained attack this degrades DB connection pool availability and query latency for all users of the mirror node REST API, constituting a denial-of-service against the service's database tier. The `/transactions/:transactionIdOrHash` path is fully unmitigated by caching, making it the highest-severity surface.

### Likelihood Explanation
Staking reward transfers are a normal, publicly observable part of Hedera network activity. An attacker needs no credentials, no special knowledge beyond a list of timestamps of staking-reward transactions (obtainable from the same public API), and no elevated privileges. The attack is trivially scriptable: enumerate timestamps with staking reward transfers, then replay them at high frequency. The only friction is the Redis cache for the `/transactions` list endpoint, which is bypassed by timestamp rotation or Redis unavailability.

### Recommendation
1. **Gate the secondary query on a fast in-memory pre-check** that is already done — `getStakingRewardTimestamps()` already filters rows client-side. The query is only issued when that list is non-empty, which is correct. The remaining gap is the lack of rate limiting.
2. **Add per-IP or global rate limiting** at the API gateway or Express middleware layer for all `/transactions` endpoints.
3. **Cache the staking reward query results** independently (e.g., keyed by the sorted set of timestamps) so that repeated requests for the same set of timestamps — even across different top-level requests — do not re-hit the DB.
4. **For `getTransactionsByIdOrHash`**, apply the same Redis caching wrapper used in `doGetTransactions` to `formatTransactionRows` results, or cache the staking reward sub-query result separately.

### Proof of Concept

```
# Step 1: Discover timestamps of transactions with staking reward transfers (entity 800)
GET /api/v1/transactions?limit=100
# Inspect response: find consensus_timestamps where transfers[] contains account "0.0.800"

# Step 2: High-frequency replay with rotating unique timestamps
for ts in <list_of_staking_reward_timestamps>:
    GET /api/v1/transactions?timestamp=<ts>
    # Each unique ts is a cache miss → triggers secondary DB query to staking_reward_transfer table

# Step 3: For fully unmitigated amplification, use the by-ID endpoint
# (no caching at all on this path)
for txid in <list_of_transaction_ids_with_staking_rewards>:
    GET /api/v1/transactions/<txid>
    # Every request → formatTransactionRows → createStakingRewardTransferList → DB query
```

Each iteration of the loop causes one extra `SELECT … FROM staking_reward_transfer WHERE consensus_timestamp IN (…)` beyond the primary transaction query, with no server-side mechanism to prevent an unprivileged user from sustaining this at arbitrary frequency.

### Citations

**File:** rest/transactions.js (L191-192)
```javascript
const formatTransactionRows = async (rows) => {
  const stakingRewardMap = await createStakingRewardTransferList(rows);
```

**File:** rest/transactions.js (L253-257)
```javascript
const createStakingRewardTransferList = async (transactions) => {
  const stakingRewardTimestamps = getStakingRewardTimestamps(transactions);
  const rows = await getStakingRewardTransferList(stakingRewardTimestamps);
  return convertStakingRewardTransfers(rows);
};
```

**File:** rest/transactions.js (L265-282)
```javascript
const getStakingRewardTransferList = async (stakingRewardTimestamps) => {
  if (stakingRewardTimestamps.length === 0) {
    return [];
  }

  const positions = range(1, stakingRewardTimestamps.length + 1).map((position) => `$${position}`);
  const query = `
      select ${StakingRewardTransfer.CONSENSUS_TIMESTAMP},
             json_agg(json_build_object(
                     'account', ${StakingRewardTransfer.ACCOUNT_ID},
                     '${StakingRewardTransfer.AMOUNT}', ${StakingRewardTransfer.AMOUNT})) as staking_reward_transfers
      from ${StakingRewardTransfer.tableName}
      where ${StakingRewardTransfer.CONSENSUS_TIMESTAMP} in (${positions})
      group by ${StakingRewardTransfer.CONSENSUS_TIMESTAMP}`;

  const {rows} = await pool.queryQuietly(query, stakingRewardTimestamps);
  return rows;
};
```

**File:** rest/transactions.js (L703-705)
```javascript
  const loader = (keys) => getTransactionsDetails(keys, order).then((result) => formatTransactionRows(result.rows));

  const transactions = await cache.get(payerAndTimestamps, loader, keyMapper);
```

**File:** rest/transactions.js (L960-960)
```javascript
  const transactions = await formatTransactionRows(rows);
```

**File:** rest/cache.js (L99-101)
```javascript
    if (!this.ready) {
      return loader(keys);
    }
```
