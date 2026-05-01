### Title
Unauthenticated Historical Hook Storage Query Enables Resource Exhaustion via Unbounded Timestamp Range and Maximum Key IN Clause

### Summary
Any unauthenticated user can trigger the expensive historical code path in `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` by supplying any `timestamp=` parameter alongside up to 100 `key=eq:` values. This causes `findByKeyInAndTimestampBetween()` to execute a `SELECT DISTINCT ON (key) ... WHERE key IN (100 values) AND consensus_timestamp BETWEEN 0 AND Long.MAX_VALUE` query against the partitioned `hook_storage_change` table, which is substantially more expensive than the non-historical `hook_storage` IN lookup. No authentication or rate limiting exists in the `rest-java` module to prevent repeated invocation.

### Finding Description

**Exact code path:**

`HooksController.java` lines 104–130 accepts `timestamp` with `@Size(max = 2)` and `keys` with `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` (= 100), both with no authentication guard.

`Bound.of()` (`Bound.java` lines 169–182) converts any single `timestamp=gte:0` into a `Bound` with `lower=0`, `upper=null`. `getAdjustedLowerRangeValue()` (line 86–97) returns `0` when `lower == null`, and `adjustUpperBound()` (line 63–74) returns `Long.MAX_VALUE` when `upper == null`. This means a single `timestamp=gte:0` parameter produces a BETWEEN spanning the entire table.

`HookStorageRequest.isHistorical()` (line 66–68) returns `true` whenever `timestamp` is non-empty, routing to `getHookStorageChange()` in `HookServiceImpl.java` (lines 84–118).

Inside `getHookStorageChange()`, at line 103–105, when `requestHasKeys` is true, the code calls:
```java
hookStorageChangeRepository.findByKeyInAndTimestampBetween(
    ownerId.getId(), hookId, keys, timestampLowerBound, timestampUpperBound, page);
```
where `keys` is the full raw list (up to 100 entries) and `timestampLowerBound=0`, `timestampUpperBound=Long.MAX_VALUE`.

The resulting SQL (`HookStorageChangeRepository.java` lines 41–63) is:
```sql
SELECT DISTINCT ON (key) ...
FROM hook_storage_change
WHERE owner_id = :ownerId
  AND hook_id = :hookId
  AND key IN (:keys)                          -- up to 100 values
  AND consensus_timestamp BETWEEN 0 AND 9223372036854775807  -- all partitions
```

**Root cause:** The `distinct on (key)` operator requires PostgreSQL to sort all matching rows by key and then pick the latest per key. The `hook_storage_change` table is range-partitioned by `consensus_timestamp` (migration `V2.17.1__add_hooks_support.sql` lines 47–54). An unbounded timestamp range forces the planner to scan every partition. The non-historical path queries `hook_storage` (one row per `(owner_id, hook_id, key)`) with a direct primary-key IN lookup — no sort, no partition fan-out.

**Why existing checks fail:**
- `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` caps keys at 100 but does not prevent the expensive query; 100 keys is the designed maximum.
- `@Size(max = 2)` on timestamps only prevents more than 2 timestamp parameters; a single `timestamp=gte:0` is fully valid.
- The `rest-java` module has no rate limiter (the `ThrottleConfiguration`/`ThrottleManagerImpl` classes exist only in the `web3` module).
- No authentication annotation (`@PreAuthorize`, `@Secured`, etc.) is present on `getHookStorage()`.

### Impact Explanation

Each request forces a full cross-partition sequential scan of `hook_storage_change` with a sort for `DISTINCT ON`. In a production system with months of hook storage history across many time partitions, a single request can consume orders of magnitude more DB CPU and I/O than the equivalent non-historical request. An attacker sending a sustained stream of such requests (each valid, each within all declared parameter limits) can drive database CPU and I/O well above the 30% threshold relative to baseline, degrading or denying service to legitimate users. The `limit` cap (max 100) only restricts returned rows, not the rows scanned before the sort and deduplication.

### Likelihood Explanation

The attack requires zero privileges, zero account setup, and zero knowledge beyond a valid `ownerId` and `hookId` (both are enumerable from the public `/api/v1/accounts/{ownerId}/hooks` endpoint). The exploit is a single HTTP GET request with well-formed parameters. It is fully repeatable in a tight loop from a single client or distributed across multiple IPs. No brute force is involved; every request is semantically valid and processed to completion.

### Recommendation

1. **Require a bounded timestamp range for historical queries**: Reject requests where the timestamp range exceeds a configurable maximum window (e.g., 24 hours), consistent with how other historical endpoints are protected.
2. **Add rate limiting to `rest-java`**: Apply a per-IP or global request-rate bucket (analogous to `ThrottleConfiguration` in `web3`) to the hook storage endpoint.
3. **Cap the effective timestamp lower bound**: If no lower bound is supplied, default to `now() - maxWindow` rather than `0`, preventing full-history scans.
4. **Add a query timeout**: Configure a statement timeout on the DB connection pool for REST API queries to bound worst-case execution time.

### Proof of Concept

```
# Generate 100 key=eq: parameters (all valid 32-byte hex values)
KEYS=$(python3 -c "
for i in range(100):
    print(f'key=eq:0x{i:064x}', end='&')
")

# Single request triggering full cross-partition scan
curl -s "http://<mirror-node>/api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0&${KEYS}limit=100"

# Sustained attack loop
while true; do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0&${KEYS}limit=100" &
done
```

Each iteration executes:
```sql
SELECT DISTINCT ON (key) owner_id, hook_id, key, value_written, ...
FROM hook_storage_change
WHERE owner_id = 123
  AND hook_id = 1
  AND key IN (0x000...000, 0x000...001, ..., 0x000...063)  -- 100 values
  AND consensus_timestamp BETWEEN 0 AND 9223372036854775807
ORDER BY key ASC, consensus_timestamp DESC
LIMIT 100;
```

This scans all time partitions of `hook_storage_change` for the given owner/hook, performing a sort-based deduplication, while the non-historical equivalent performs 100 direct primary-key lookups on `hook_storage`.