### Title
Unbounded Timestamp Range in `getOneAccount()` Enables Unauthenticated DB I/O Saturation DoS

### Summary
`getOneAccount()` in `rest/accounts.js` calls `parseTimestampFilters` with `validateRange=false`, explicitly bypassing the `maxTimestampRange` (default 7 days) guard. With `bindTimestampRange` disabled by default, an unauthenticated attacker can supply a decades-wide timestamp range that is passed unmodified into multiple parallel DB queries, exhausting the 10-connection pool and causing sustained request queuing across the entire REST API.

### Finding Description

**Root cause — `validateRange=false` at line 413:**

```js
// rest/accounts.js:413
const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
//                                                                                          ^^^^^ validateRange=false
```

In `parseTimestampFilters` (`rest/utils.js:1657-1665`), the `validateRange` flag is the only gate that enforces `maxTimestampRangeNs` (default 7 days = `604800000000000n` ns). With it set to `false`, any range — including `gte:0` to `lte:99999999999.999999999` (spanning decades) — is accepted without error.

**No capping in the transaction path — `bindTimestampRange=false` default:**

`getTransactionTimestamps` (`rest/transactions.js:464-468`) calls `bindTimestampRange`, which is the only other mechanism that could cap the range. Its config default is `false` (`docs/configuration.md:579`):

```
hiero.mirror.rest.query.bindTimestampRange | false
```

When `false`, `bindTimestampRange` returns the range unchanged (`rest/timestampRange.js:20-22`).

**Parallel DB query fan-out — `Promise.all` at line 495:**

```js
// rest/accounts.js:487-495
const entityPromise = pool.queryQuietly(entityQuery, entityParams);
const transactionsPromise = includeTransactions
  ? transactions.doGetTransactions(filters, req, timestampRange)
  : emptyTransactionsPromise;
const [entityResults, transactionResults] = await Promise.all([entityPromise, transactionsPromise]);
```

With `transactions=true` (default), each single HTTP request spawns at minimum 3–4 concurrent DB queries:
1. `getAccountBalanceTimestampRange` (sequential, before `Promise.all`)
2. Entity query (inside `Promise.all`)
3. `getTransactionTimestamps` — multi-table UNION/FULL OUTER JOIN across `transaction`, `crypto_transfer`, `token_transfer`, `entity_transaction` with the unbounded range
4. `getTransactionsDetails` (after timestamps resolve)

The token-balance subquery inside the entity query also scans `consensus_timestamp >= lower AND consensus_timestamp <= upper` with `limit 1000`, potentially spanning many partitions.

**DB pool exhaustion:**

The pool is capped at `maxConnections: 10` (`docs/configuration.md:556`). With 3–4 connections consumed per request and a `statementTimeout` of 20 s, only 2–3 concurrent attacker requests are needed to hold all connections, causing all legitimate requests to queue for up to `connectionTimeout: 20000 ms`.

**No rate limiting:** `grep` across `rest/**/*.js` finds no rate-limiting middleware.

### Impact Explanation

An attacker holding the 10-connection pool for 20 s (statement timeout) with 3 concurrent requests causes a complete REST API outage for that duration. Repeated at ~20 s intervals, this is a continuous, low-bandwidth DoS. All endpoints sharing the pool — including ingestion-status and network endpoints — are affected. The mirror node's ability to serve any data is degraded proportionally to the pool saturation level.

### Likelihood Explanation

- **No authentication required** — the `/api/v1/accounts/{id}` endpoint is public.
- **No rate limiting** — confirmed absent in the codebase.
- **Trivially reproducible** — a single `curl` loop with 3 parallel processes suffices.
- **Low bandwidth** — the attack payload is a short URL; no large body is needed.
- **Stable** — the misconfiguration (`validateRange=false`) is hardcoded, not a transient race condition.

### Recommendation

1. **Remove `validateRange=false`** from the `parseTimestampFilters` call in `getOneAccount` (`rest/accounts.js:413`). Open-ended ranges (no upper bound) are already handled by `allowOpenRange=true`; the range-size check only fires when both bounds are present, so removing `validateRange=false` does not break the open-range use case.
2. **Enable `bindTimestampRange=true` by default** or enforce it specifically for the accounts transaction sub-path, so that even if a wide closed range is supplied, it is capped to `maxTransactionsTimestampRange` (default 60 days) before hitting the DB.
3. **Add API-level rate limiting** (e.g., express-rate-limit) per IP on all `/api/v1/` routes.
4. **Increase `maxConnections`** or add a per-request DB connection timeout shorter than `statementTimeout` to reduce blast radius.

### Proof of Concept

```bash
# Three concurrent requests with a decades-wide timestamp range, transactions=true (default)
for i in 1 2 3; do
  curl -s "http://<mirror-node>:5551/api/v1/accounts/0.0.1234?\
timestamp=gte:0\
&timestamp=lte:99999999999.999999999" &
done
wait
```

Each request bypasses `maxTimestampRange` validation (line 413, `validateRange=false`), passes the unbounded range through `bindTimestampRange` unchanged (disabled by default), and fans out 3–4 long-running DB queries via `Promise.all` (line 495). With the pool at 10 connections, 3 concurrent requests hold all connections for up to 20 s (statement timeout), blocking all other API consumers.