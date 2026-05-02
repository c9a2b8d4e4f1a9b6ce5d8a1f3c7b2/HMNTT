### Title
Permanent Cache Poisoning via TTL-less `mset` Storing Incomplete Transaction Data During DB Partition

### Summary
In `doGetTransactions()`, transaction detail objects fetched from a degraded DB (returning null `crypto_transfer_list`/`token_transfer_list` due to a network partition affecting those tables) are stored in Redis via `mset` with **no TTL**. Because the cache key is per-timestamp and the entry never expires, all subsequent users receive permanently incomplete transaction data for those timestamps even after the partition heals. No privileges are required to trigger this — any unauthenticated GET `/transactions` request during the partition window is sufficient.

### Finding Description

**Exact code path:**

`rest/transactions.js` `doGetTransactions()` (lines 695–723):
```
getTransactionTimestamps()  →  payerAndTimestamps  (first DB query)
loader = (keys) => getTransactionsDetails(keys, order).then(...)  (second DB query)
cache.get(payerAndTimestamps, loader, keyMapper)
```

`rest/cache.js` `Cache.get()` (lines 112–131):
```javascript
const missing = await loader(missingKeys);          // calls getTransactionsDetails()
// ... fills values[] with loader results ...
this.redis.mset(newValues)                          // NO TTL — permanent storage
```

**Root cause:** `mset` (line 130, `rest/cache.js`) stores transaction objects with **no expiry**. The `setSingle()` method uses `setex` with a TTL, but `get()` uses `mset` unconditionally.

**How partial results arise:** `getTransactionsDetails()` (`rest/transactions.js` lines 616–663) executes a CTE query joining `transaction`, `crypto_transfer`, and `token_transfer`. In a partial partition (e.g., read replica lag, or the transfer tables are on a different shard/node that is temporarily unreachable), the `transaction` table returns rows but the CTE subqueries for `c_list` and `t_list` return no rows — PostgreSQL returns the transaction row with `crypto_transfer_list = NULL` and `token_transfer_list = NULL`. This is valid SQL behavior, not an error.

`queryQuietly` (`rest/utils.js` lines 1481–1545) only throws `DbError` on a hard failure (line 1539). A degraded-but-responding DB returning NULL subquery results does **not** throw — it returns rows normally.

`formatTransactionRows()` (`rest/transactions.js` lines 191–224) maps `NULL` transfer lists to empty arrays (`transfers: []`, `token_transfers: []`). These well-formed but incomplete objects are then stored permanently in Redis.

**Why existing checks fail:**
- No TTL is set on `mset` — entries persist until Redis memory eviction or restart.
- No validation that `transfers` or `token_transfers` are non-empty before caching.
- No cache invalidation mechanism exists for these per-timestamp keys.
- The `keyMapper` (`rest/transactions.js` lines 679–685) maps only on `consensus_timestamp`, so the same key is reused by all future requests for that timestamp regardless of completeness.

### Impact Explanation
Any transaction whose timestamp was cached during the partition window will permanently serve empty `transfers` and `token_transfers` arrays to all users. This corrupts the audit trail for those transactions — balance changes, token movements, and fee transfers become invisible. The impact is data integrity loss at the API layer, not just a transient availability issue. Severity is high because: (1) the corruption is silent (HTTP 200 with structurally valid but incomplete JSON), (2) it affects all users globally (shared Redis), and (3) it persists indefinitely.

### Likelihood Explanation
The precondition is a partial DB partition (not a total outage), which is a realistic infrastructure event in any deployment using read replicas, connection poolers, or partitioned PostgreSQL. The attacker does not need to cause the partition — they only need to issue a normal unauthenticated GET `/transactions` request during the window. The attack is repeatable: any request during any future partition event re-triggers it. No credentials, no special headers, no rate-limit bypass required.

### Recommendation
1. **Add TTL to `mset`**: Replace `this.redis.mset(newValues)` with pipeline calls using `setex` and a bounded TTL (e.g., matching the response cache TTL). This is the primary fix.
2. **Validate completeness before caching**: In the `loader`, verify that returned transaction objects have non-null transfer data before allowing them to be stored. If the DB returns a transaction row with null CTEs, treat it as a cache miss.
3. **Guard against null transfer lists**: In `formatTransactionRows()`, if `crypto_transfer_list` is null for a transaction that is known to have transfers (e.g., non-zero `charged_tx_fee`), propagate an error rather than silently returning `[]`.

### Proof of Concept

**Preconditions:**
- Redis enabled and ready
- PostgreSQL read replica accessible, but `crypto_transfer` / `token_transfer` tables temporarily returning no rows (simulate via: `ALTER TABLE crypto_transfer DISABLE TRIGGER ALL` + network rule blocking that table's partition, or replica lag exceeding the query window)

**Steps:**
1. Confirm transactions with known transfers exist at timestamps T1, T2, T3.
2. Induce partial partition: make `crypto_transfer` and `token_transfer` tables return empty results while `transaction` table remains accessible.
3. As an unauthenticated user, issue: `GET /api/v1/transactions`
4. Observe: response returns transactions with `"transfers": []` and `"token_transfers": []`.
5. Restore the DB to full health.
6. As a different unauthenticated user, issue the same request: `GET /api/v1/transactions`
7. **Observe**: response still returns `"transfers": []` and `"token_transfers": []` — served from Redis with no TTL, permanently poisoned.
8. Confirm via `redis-cli KEYS "transaction:*"` that entries exist with no TTL (`TTL` returns `-1`).