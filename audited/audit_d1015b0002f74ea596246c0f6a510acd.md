### Title
Unauthenticated Concurrent Requests to `/contracts/:contractId/results/logs` Trigger Unbounded Correlated Subqueries on `record_file`, Enabling DB Griefing

### Summary
The `getContractLogs()` function in `rest/service/contractService.js` collects all unique `consensus_timestamp` values from a paginated result set and passes them as an array to `RecordFileService.getRecordFileBlockDetailsFromTimestampArray()`. That function executes a SQL query containing a correlated subquery that performs one index-range scan on the `record_file` table per timestamp. Because the REST endpoint has no rate limiting or concurrency control, any unauthenticated user can flood the endpoint with concurrent requests, multiplying the number of simultaneous correlated subqueries against the `record_file` table and degrading database performance.

### Finding Description

**Code path:**

`rest/routes/contractRoute.js:16` → `ContractController.getContractLogsById` (`rest/controllers/contractController.js:779`) → `ContractService.getContractLogs()` (`rest/service/contractService.js:376`) → `RecordFileService.getRecordFileBlockDetailsFromTimestampArray()` (`rest/service/recordFileService.js:92`)

**Root cause — step 1, timestamp array construction:**

```js
// contractService.js lines 383-390
const timestamps = [];
rows.forEach((row) => {
  if (row.consensus_timestamp !== timestamps[timestamps.length - 1]) {
    timestamps.push(row.consensus_timestamp);
  }
});
const recordFileMap = await RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps);
```

`rows` contains up to `limit` entries (default 25, max 100). Each unique `consensus_timestamp` is appended, so the array can hold up to `limit` entries.

**Root cause — step 2, correlated subquery per timestamp:**

```sql
-- recordFileService.js lines 23-43
where consensus_end in (
  select (
    select consensus_end
    from record_file
    where consensus_end >= timestamp and
      consensus_end >= $2 and
      consensus_end <= $3
    order by consensus_end
    limit 1
  ) as consensus_end
  from (select unnest($1::bigint[]) as timestamp) as tmp
  group by consensus_end
)
```

`unnest($1::bigint[])` expands the array into rows; for each row the inner correlated subquery performs an index-range scan on `record_file`. With N timestamps, N index scans execute in a single query. With C concurrent HTTP requests, `C × N` index scans hit the database simultaneously.

**Why existing checks are insufficient:**

- The `limit` parameter is validated and bounded (max 100), but this only caps the per-request cost, not the aggregate concurrent cost.
- The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` Java module for `eth_call`-style endpoints; it is entirely absent from the Node.js REST service that serves `/contracts/:contractId/results/logs`.
- No IP-based rate limiting, no concurrency semaphore, and no connection-pool guard is applied to this route.

### Impact Explanation
An attacker can degrade database query throughput for all users of the mirror node REST API. The `record_file` table is queried with correlated subqueries proportional to `C × limit` simultaneously. Even though each individual subquery is an indexed lookup, saturating the PostgreSQL connection pool or the I/O scheduler with hundreds of simultaneous range scans causes query latency to rise across all endpoints sharing the same database. This is a griefing-class denial-of-service with no direct economic damage to network participants, matching the stated scope.

### Likelihood Explanation
No authentication, API key, or proof-of-work is required. The attack requires only an HTTP client capable of issuing concurrent GET requests to a public endpoint. The endpoint is publicly documented and reachable. The attack is trivially repeatable and scriptable (e.g., `ab`, `wrk`, or a simple async loop). A single attacker with a modest internet connection can sustain the load indefinitely.

### Recommendation
1. **Add per-IP rate limiting** to the REST service (e.g., via an Express middleware such as `express-rate-limit`) applied globally or specifically to expensive endpoints like `/contracts/:contractId/results/logs`.
2. **Rewrite the correlated subquery** in `recordFileBlockDetailsFromTimestampArrayQuery` to avoid per-timestamp index scans; a single range query with a lateral join or a CTE that resolves all timestamps in one pass would reduce the per-request DB cost.
3. **Add a global concurrency limiter** (e.g., `p-limit` or a semaphore) around calls to `getRecordFileBlockDetailsFromTimestampArray()` to cap simultaneous in-flight DB queries.
4. **Enforce a hard maximum on `limit`** at the framework level and document it, so the per-request timestamp array size is provably bounded.

### Proof of Concept

**Preconditions:**
- A contract exists on the network with at least 25 logs spread across distinct consensus timestamps (trivially satisfiable on mainnet/testnet).
- The mirror node REST API is publicly accessible.

**Steps:**
```bash
# Replace CONTRACT_ID with a real contract that has many logs
CONTRACT_ID="0.0.1000"
MIRROR_URL="https://<mirror-node-host>/api/v1"

# Send 500 concurrent requests, each fetching the maximum page of logs
ab -n 5000 -c 500 \
  "${MIRROR_URL}/contracts/${CONTRACT_ID}/results/logs?limit=100&order=desc"
```

**Expected result:**
- Each of the 500 concurrent requests triggers a call to `getRecordFileBlockDetailsFromTimestampArray()` with up to 100 timestamps.
- Up to 50,000 correlated subqueries execute simultaneously against the `record_file` table.
- Database query latency for all other API consumers rises measurably; under sustained load the connection pool exhausts and requests begin timing out or returning 500 errors.