### Title
Unauthenticated Forced Routing to Expensive `DISTINCT ON` Historical Query via Trivial Timestamp Parameter

### Summary
Any unauthenticated external user can force `getHookStorage()` to always execute the significantly more expensive `getHookStorageChange()` code path by supplying any non-empty `timestamp` query parameter. Combined with the default maximum key range and repeated concurrent requests, this triggers unbounded `DISTINCT ON` full-range scans against the `hook_storage_change` table with no rate limiting on the `rest-java` hooks endpoint, enabling sustained resource exhaustion.

### Finding Description

**Exact code path:**

In `HookServiceImpl.java`, the routing decision is:

```java
// HookServiceImpl.java lines 56-59
public HookStorageResult getHookStorage(HookStorageRequest request) {
    if (request.isHistorical()) {
        return getHookStorageChange(request);  // expensive path
    }
    // ... cheap current-state path
}
```

`isHistorical()` is defined in `HookStorageRequest.java` lines 66-68:

```java
public boolean isHistorical() {
    return !timestamp.isEmpty();
}
```

`Bound.isEmpty()` returns `true` only when both `lower` and `upper` are null (Bound.java line 127). Supplying a single `timestamp=gte:0` sets `lower` to a non-null value, making `isEmpty()` return `false`, and `isHistorical()` return `true` — unconditionally routing to `getHookStorageChange()`.

**The expensive query** (`HookStorageChangeRepository.java` lines 15-39):

```sql
SELECT DISTINCT ON (key)
     owner_id, hook_id, key, value_written as "value", ...
FROM hook_storage_change
WHERE owner_id = :ownerId
  AND hook_id = :hookId
  AND key >= :keyLowerBound
  AND key <= :keyUpperBound
  AND consensus_timestamp BETWEEN :timestampLowerBound AND :timestampUpperBound
```

With `timestamp=gte:0`:
- `timestampLowerBound` = 0 (from `getAdjustedLowerRangeValue()`, Bound.java line 86-97)
- `timestampUpperBound` = `Long.MAX_VALUE` (from `adjustUpperBound()` when `upper == null`, Bound.java line 63-74)
- `keyLowerBound` = `0x00...00` (32 zero bytes, HooksController.java line 61)
- `keyUpperBound` = `0xFF...FF` (32 0xFF bytes, HooksController.java lines 71-72)

This forces a full table scan of `hook_storage_change` for the given `(ownerId, hookId)` pair, with `DISTINCT ON (key)` requiring PostgreSQL to sort/group all matching rows before applying the `LIMIT`. The `LIMIT` (capped at 100 via `@Max(MAX_LIMIT)`) only restricts returned rows — it does **not** reduce the rows scanned before the `DISTINCT ON` deduplication.

**Root cause:** `isHistorical()` treats any non-empty `Bound` as a historical request with no validation that the timestamp range is meaningfully constrained. The default key range is the widest possible (full 32-byte space). No rate limiting exists on the `rest-java` hooks endpoint — the `ThrottleConfiguration`/`ThrottleManagerImpl` throttling is scoped exclusively to the `web3` module.

**Why checks fail:**
- `@Size(max = 2)` on `timestamps` (HooksController.java line 110): limits to 2 params, but one is sufficient
- `@Max(MAX_LIMIT)` on `limit` (line 112): limits returned rows, not scanned rows
- `@Min(0)` on `hookId` (line 107): validates format only, not existence
- No authentication, no per-IP rate limiting, no query timeout enforcement visible in `rest-java`

### Impact Explanation
An attacker repeatedly issuing `GET /api/v1/accounts/{any_valid_id}/hooks/{hookId}/storage?timestamp=gte:0` forces the database to execute full-range `DISTINCT ON` scans against the append-only `hook_storage_change` table on every request. As the table grows with network activity, each such request becomes progressively more expensive. Concurrent flooding of this endpoint from a single IP (or distributed) can saturate database CPU and I/O, degrading or denying service to all mirror node consumers. This is a resource exhaustion / DoS vector with no privilege requirement.

### Likelihood Explanation
The exploit requires zero authentication, zero on-chain interaction, and zero specialized knowledge — only the ability to send HTTP GET requests with a `timestamp` query parameter. The endpoint is publicly documented in the OpenAPI spec (`rest/api/v1/openapi.yml` line 90). Any attacker who reads the API docs can trigger this. It is trivially scriptable and repeatable at high frequency.

### Recommendation
1. **Require a meaningful upper timestamp bound**: Reject requests where `timestamp` is provided but `upper` is null (i.e., open-ended historical scans). Enforce `timestamp=lte:<value>` alongside any `gte` to bound the scan window.
2. **Add rate limiting to the `rest-java` hooks endpoint**: Apply per-IP or global request-rate throttling analogous to the `web3` `ThrottleManagerImpl`, specifically for the `/hooks/{hookId}/storage` endpoint.
3. **Add a statement timeout** at the JDBC/datasource level for queries issued by `HookStorageChangeRepository` to prevent runaway scans.
4. **Consider a maximum timestamp range width**: Reject requests where `timestampUpperBound - timestampLowerBound` exceeds a configurable threshold.

### Proof of Concept

**Preconditions:** Mirror node is running with some `hook_storage_change` data populated (any active network with hook executions).

**Step 1 — Trigger the expensive path with a single request:**
```
GET /api/v1/accounts/0.0.1/hooks/1/storage?timestamp=gte:0
```
- `timestamp=gte:0` → `Bound.lower` is non-null → `isHistorical()` = `true`
- Routes to `getHookStorageChange()` with `timestampLowerBound=0`, `timestampUpperBound=Long.MAX_VALUE`, full key range
- PostgreSQL executes: `SELECT DISTINCT ON (key) ... FROM hook_storage_change WHERE ... AND consensus_timestamp BETWEEN 0 AND 9223372036854775807`

**Step 2 — Amplify with concurrent requests (no auth required):**
```bash
for i in $(seq 1 200); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1/hooks/1/storage?timestamp=gte:0" &
done
wait
```

**Step 3 — Vary `ownerId`/`hookId` to defeat any per-entity caching:**
```bash
for i in $(seq 1 100); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.$i/hooks/$i/storage?timestamp=gte:0" &
done
```

**Expected result:** Database CPU and I/O spike proportionally to `hook_storage_change` table size; legitimate API requests experience increased latency or timeouts; node resource consumption increases well beyond 30% compared to baseline.