### Title
Unbounded Timestamp Range in `extractContractLogsMultiUnionQuery` for Contract-Specific Log Queries Enables Full Table Scan DoS

### Summary
When `getContractLogsById` calls `extractContractLogsMultiUnionQuery` with a `contractId`, the function explicitly skips `optimizeTimestampFilters` (and therefore `bindTimestampRange`) due to the `contractId === undefined` guard at line 678. An unprivileged user can supply `timestamp=gte:0` with no upper bound, causing the database to scan the entire `contract_log` table for that contract with no range restriction, exhausting DB CPU and I/O.

### Finding Description
**Exact code path:**

In `rest/controllers/contractController.js`, `extractContractLogsMultiUnionQuery` (line 582) contains the following branch at line 678:

```js
} else if (contractId === undefined) {
  // Optimize timestamp filters only when there is no transaction hash and transaction id
  const {filters: timestampFilters, next} = await optimizeTimestampFilters(bounds.primary.getAllFilters(), order);
  ...
}
```

When `contractId` is defined (i.e., the `/contracts/:contractId/results/logs` endpoint via `getContractLogsById`, line 802), this entire block is skipped. `optimizeTimestampFilters` (line 384) is the only place that calls `bindTimestampRange`, which is the only mechanism that could cap the timestamp range.

**Root cause:** The assumption that a `contractId` filter is sufficient to bound the query is incorrect. A contract with a long history can have millions of log entries, and a timestamp filter of `gte:0` (epoch 0, year 1970) with no upper bound produces a query like:

```sql
WHERE cl.contract_id = $1 AND cl.consensus_timestamp >= 0
ORDER BY cl.consensus_timestamp DESC, cl.index DESC
LIMIT 25
```

This forces a full index scan over all historical logs for that contract.

**Why existing checks fail:**

1. `checkTimestampsForTopics` (line 786) only validates timestamp range when topic filters are present. Without topics, it is a no-op.
2. `alterTimestampRange` (line 785) only normalizes `gte+lte` to `eq` when both have the same value — it does not enforce any range.
3. `utils.buildAndValidateFilters` validates timestamp *format* (`/^\d{1,10}$/`) but not the *value* or *range span*.
4. `bindTimestampRange` in `rest/timestampRange.js` (line 20) is gated by `queryConfig.bindTimestampRange`, which defaults to `false` per documentation (`hiero.mirror.rest.query.bindTimestampRange: false`). Even if it were reached, it would be a no-op by default.
5. For the global `/contracts/results/logs` endpoint (`getContractLogs`, line 835), `optimizeTimestampFilters` IS called, but `parseTimestampFilters` is invoked with `validateRange=false` (line 387: 6th argument), explicitly disabling the `maxTimestampRange` (7-day) check.

### Impact Explanation
An attacker can repeatedly issue requests to `/api/v1/contracts/{contractId}/results/logs?timestamp=gte:0` for any known contract (e.g., a high-activity DeFi contract with millions of log entries). Each request forces the database to perform an unbounded sequential scan of `contract_log` filtered only by `contract_id`, consuming significant CPU and I/O. With the DB pool capped at 10 connections by default (`maxConnections: 10`), a small number of concurrent such requests can saturate the pool and degrade or deny service to all other API consumers. This aligns with the stated severity of ≥30% network processing node disruption without brute force.

### Likelihood Explanation
- **No authentication required**: The endpoint is public.
- **Trivial to exploit**: A single HTTP GET with `?timestamp=gte:0` is sufficient.
- **Repeatable**: The attacker can issue requests in a loop or from multiple IPs.
- **Target discovery is easy**: Active contract addresses are publicly visible on-chain.
- **Default configuration is vulnerable**: `bindTimestampRange` defaults to `false`, and the by-ID path bypasses it entirely regardless.

### Recommendation
1. **Remove the `contractId === undefined` guard** that skips `optimizeTimestampFilters`. Apply timestamp range optimization and bounding for all callers of `extractContractLogsMultiUnionQuery`, including the by-ID path.
2. **Enable `bindTimestampRange: true` by default**, or enforce a hard maximum timestamp span (e.g., 7 days) unconditionally in `extractContractLogsMultiUnionQuery` regardless of whether `contractId` is present.
3. **Pass `validateRange=true`** when calling `parseTimestampFilters` inside `optimizeTimestampFilters` (line 387) so the `maxTimestampRange` config is enforced.
4. **Require an upper-bound timestamp** when no `eq` operator is used, rejecting open-ended lower-bound-only queries.

### Proof of Concept
**Preconditions:** Mirror node REST API is publicly accessible. A contract with significant log history exists (e.g., `0.0.1234`).

**Trigger:**
```bash
# Single request — forces full contract_log scan from epoch 0
curl "https://<mirror-node>/api/v1/contracts/0.0.1234/results/logs?timestamp=gte:0&order=desc"

# Concurrent flood to exhaust DB pool (default: 10 connections)
for i in $(seq 1 20); do
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.1234/results/logs?timestamp=gte:0&order=desc" &
done
wait
```

**Result:** Each request issues an unbounded `WHERE cl.contract_id = $1 AND cl.consensus_timestamp >= 0` query. With 10–20 concurrent requests, the DB connection pool is saturated, causing all other API requests to time out (default `statementTimeout: 20000ms`), effectively denying service.