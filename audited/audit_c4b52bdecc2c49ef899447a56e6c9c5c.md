### Title
Unauthenticated Timestamp Filter Triggers Unconditional UNION Query Against `entity_history` in `getContractById`, No Rate Limiting

### Summary
Any unprivileged user can supply a `timestamp` query parameter to `GET /api/v1/contracts/:contractId` to unconditionally trigger a UNION query across both the `entity` and `entity_history` tables. The `getContractById` handler passes timestamp filters directly to `extractTimestampRangeConditionFilters` without invoking `parseTimestampFilters` (which enforces `maxTimestampRange`), and no rate limiting exists at the REST API layer. Concurrent requests each carrying any timestamp filter double the per-request database read surface compared to the no-timestamp path.

### Finding Description
**Code path:**

`rest/routes/contractRoute.js:13` → `ContractController.getContractById` (`rest/controllers/contractController.js:707-737`) → `extractTimestampRangeConditionFilters` (`rest/utils.js:709-756`) → `getContractByIdOrAddressContractEntityQuery` (`rest/controllers/contractController.js:179-208`)

**Root cause:**

`acceptedContractByIdParameters` is defined as `new Set([filterKeys.TIMESTAMP])` (line 1332). The handler calls `utils.buildAndValidateFilters` which validates only the *format* of individual timestamp values, then calls `utils.extractTimestampRangeConditionFilters` which converts each filter directly to a PostgreSQL range-overlap condition (`c.timestamp_range && $N`) with no span validation.

The critical branch in `getContractByIdOrAddressContractEntityQuery`:

```js
if (timestampConditions.length !== 0) {
  tableUnionQueries.push(
    'union',
    getContractByIdOrAddressQueryForTable(Entity.historyTableName, conditions),
    `order by ${Entity.TIMESTAMP_RANGE} desc`,
    `limit 1`
  );
}
```

Any non-empty `timestampConditions` array — produced by even a single `?timestamp=gte:0` — unconditionally adds the `entity_history` table to the query via UNION.

**Failed assumption:** The `parseTimestampFilters` function (lines 1583-1681) contains the `maxTimestampRange` enforcement at lines 1657-1665, but it is **never called** in the `getContractById` code path. The path that does call it (`checkTimestampsForTopics`, `optimizeTimestampFilters`) is used by other endpoints, not this one.

**Why existing checks fail:**
- `buildAndValidateFilters` validates timestamp *format* only (regex match), not range span.
- `extractTimestampRangeConditionFilters` performs zero range-width validation.
- The REST API server (`rest/server.js:67-99`) applies no per-IP or per-endpoint rate limiting; the throttling found (`web3/src/main/java/.../ThrottleConfiguration.java`) applies only to the web3 module, not the Node.js REST API.

### Impact Explanation
Without a timestamp filter, `getContractById` queries only the `entity` table (one indexed lookup). With any timestamp filter, it queries both `entity` AND `entity_history` via UNION. The `entity_history` table accumulates all historical entity states and can be orders of magnitude larger than `entity`. While `LIMIT 1` bounds the result, the UNION still requires the database to evaluate both sub-queries and merge/sort results. An attacker sending N concurrent requests with timestamp filters generates 2×N table-access operations versus N without. At sufficient concurrency this exhausts database connection pool slots and query worker threads, degrading availability for all users.

### Likelihood Explanation
No authentication, API key, or privilege is required. The endpoint is publicly documented in `rest/api/v1/openapi.yml:541-558`. The trigger is a single extra query parameter (`?timestamp=gte:0`). Any script-kiddie with `curl` or a load-testing tool can reproduce this. The attack is stateless and trivially parallelisable.

### Recommendation
1. **Apply `parseTimestampFilters` with `validateRange=true` in `getContractById`** before calling `extractTimestampRangeConditionFilters`, so the existing `maxTimestampRange` (default 7 days) is enforced on this endpoint as it is on others.
2. **Add REST-API-level rate limiting** (e.g., `express-rate-limit`) in `rest/server.js`, mirroring the bucket4j throttle already present in the web3 module.
3. Consider requiring a closed range (both `gte` and `lte`) rather than allowing open-ended timestamp filters on this endpoint, since only a single entity row is ever returned.

### Proof of Concept
```bash
# Single request — forces UNION path
curl "https://<mirror-node>/api/v1/contracts/0.0.1?timestamp=gte:0&timestamp=lte:9999999999"

# DoS amplification — 200 concurrent requests, each triggering UNION
seq 200 | xargs -P200 -I{} \
  curl -s -o /dev/null \
  "https://<mirror-node>/api/v1/contracts/0.0.1?timestamp=gte:0&timestamp=lte:9999999999"
```

Without the timestamp parameters the same endpoint executes a single-table lookup. With them, every request executes a two-table UNION. Sustained at scale this exhausts the PostgreSQL connection pool and causes latency spikes or 503 responses for all API consumers.