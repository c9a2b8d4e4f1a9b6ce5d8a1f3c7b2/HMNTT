Based on my investigation of the actual code, I can verify the key technical claims in this report.

**Verified facts:**

1. Line 413 of `rest/accounts.js` — the call with `validateRange=false` (last arg) and `allowOpenRange=true` is confirmed. [1](#0-0) 

2. The `timestampRange` is forwarded directly to `transactions.doGetTransactions()` without any additional range capping. [2](#0-1) 

3. `bindTimestampRange()` in `timestampRange.js` returns the range unchanged when `queryConfig.bindTimestampRange` is false (the documented default). [3](#0-2) 

4. `getAccountBalanceTimestampRange` is called with the unbounded timestamp query before the transaction query, adding a second DB round-trip. [4](#0-3) 

---

Audit Report

## Title
Timestamp Range Validation Bypass in `getOneAccount()` Enables DB-Level DoS via Unbounded Timestamp Scans

## Summary
`getOneAccount()` in `rest/accounts.js` hardcodes `validateRange=false` and `allowOpenRange=true` in its call to `parseTimestampFilters`, bypassing the `maxTimestampRange` (default 7 days) guard that protects all other endpoints. An unauthenticated attacker can supply `timestamp=gte:0` to trigger expensive multi-table queries over the full chain history.

## Finding Description

**Root cause — `validateRange=false` disables the only range-size guard:**

The call at line 413 of `rest/accounts.js`:
```js
const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
```
passes `validateRange=false` as the last argument. [1](#0-0) 

Inside `utils.js`, the `maxTimestampRangeNs` (7-day) enforcement only executes inside the `if (validateRange)` block. With `validateRange=false`, that block is never reached, and a single-sided filter like `timestamp=gte:0` is accepted without error.

**`bindTimestampRange` does not compensate:**

`bindTimestampRange()` returns the range unchanged when `queryConfig.bindTimestampRange` is `false` (the documented default): [5](#0-4) 

Even when enabled, it caps to `maxTransactionsTimestampRangeNs` (default 60 days), not the 7-day `maxTimestampRange`.

**The unbounded range is forwarded to expensive queries:**

The `timestampRange` is passed directly to `doGetTransactions()`: [2](#0-1) 

Additionally, `getAccountBalanceTimestampRange` is called with the unbounded timestamp query before the transaction query, adding a second DB round-trip. [4](#0-3) 

## Impact Explanation
An attacker can hold DB connections and CPU for the duration of each expensive query. Because the DB connection pool is finite, a small number of concurrent requests (10–20) with `timestamp=gte:0` targeting a high-activity account (e.g., `0.0.2`, the treasury) can saturate the connection pool and degrade or block all other API responses. The primary amplification is at the DB layer, not the application layer.

## Likelihood Explanation
- No authentication required — any external user can call `GET /api/v1/accounts/{id}?timestamp=gte:0`.
- Trivially repeatable with a single `curl` loop; no special tooling needed.
- Default configuration is vulnerable — `bindTimestampRange=false` is the documented default.
- High-value targets exist — accounts like `0.0.2` (treasury) have transactions spanning the entire chain history, maximizing scan cost.

## Recommendation
1. **Remove the `validateRange=false` override** in `getOneAccount()`. If an open-ended range is intentionally needed for this endpoint, enforce a separate, explicit maximum range cap (e.g., 7 days) before forwarding to `doGetTransactions`.
2. **Enable `bindTimestampRange` by default**, or enforce it specifically for the single-account endpoint.
3. **Add a rate limit** on the `GET /api/v1/accounts/{id}` endpoint, particularly for requests with timestamp filters.
4. Consider adding a DB-level query timeout for this query path as a defense-in-depth measure.

## Proof of Concept
```bash
# Target a high-activity account with an unbounded lower timestamp
# Repeat concurrently (e.g., 10-20 times) to saturate the DB connection pool
curl "https://<mirror-node>/api/v1/accounts/0.0.2?timestamp=gte:0&limit=100"
```
This request bypasses the 7-day range check, triggers `getAccountBalanceTimestampRange` and `doGetTransactions` over the full chain history, and holds a DB connection for the duration of each query.

### Citations

**File:** rest/accounts.js (L413-413)
```javascript
  const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
```

**File:** rest/accounts.js (L435-438)
```javascript
    const {lower, upper} = await balances.getAccountBalanceTimestampRange(
      balanceSnapshotTsQuery.replaceAll(opsMap.eq, opsMap.lte),
      balanceSnapshotTsParams
    );
```

**File:** rest/accounts.js (L491-493)
```javascript
  const transactionsPromise = includeTransactions
    ? transactions.doGetTransactions(filters, req, timestampRange)
    : emptyTransactionsPromise;
```

**File:** rest/timestampRange.js (L19-22)
```javascript
const bindTimestampRange = async (range, order) => {
  if (!queryConfig.bindTimestampRange) {
    return {range};
  }
```
