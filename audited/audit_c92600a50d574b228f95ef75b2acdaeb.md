### Title
Unbounded `keys` Collection in `getHookStorageChange` Enables Resource-Exhaustion via Large IN Clause + Full Timestamp Range Scan

### Summary
`HookServiceImpl.getHookStorageChange` passes the caller-supplied `keys` collection directly to `HookStorageChangeRepository.findByKeyInAndTimestampBetween`, which embeds it verbatim into a native SQL `key in (:keys)` predicate with no server-side cap on collection size. Combined with an arbitrarily wide `consensus_timestamp BETWEEN` range and a `DISTINCT ON (key)` sort, a single unauthenticated request can force PostgreSQL to abandon composite indexes and perform a full sequential scan, consuming disproportionate DB CPU and I/O.

### Finding Description

**Code path:**

`HookServiceImpl.getHookStorage` (line 57) delegates to the private `getHookStorageChange` (line 84) whenever `request.isHistorical()` is true.

Inside `getHookStorageChange`:

```
// HookServiceImpl.java lines 89-105
final var keys        = request.getKeys();          // full, uncapped caller collection
final boolean requestHasKeys = !keys.isEmpty();
final var keysInRange = request.getKeysInRange();   // filtered subset

if (keysInRange.isEmpty() && requestHasKeys) {      // only guard: ALL keys out of range
    return new HookStorageResult(ownerId, List.of());
}
...
if (requestHasKeys) {
    changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
            ownerId.getId(), hookId, keys,           // ← passes full `keys`, not `keysInRange`
            timestampLowerBound, timestampUpperBound, page);
}
``` [1](#0-0) 

Two compounding problems:

1. **No size cap on `keys`**: `HookStorageRequest.keys` is a plain `Collection<byte[]>` with no `@Size` or any other constraint. [2](#0-1) 

2. **Full `keys` (not `keysInRange`) is forwarded**: Even if only one key is in range (satisfying the early-exit guard), the entire caller-supplied collection is passed to the repository, producing a maximally large `IN` clause. [3](#0-2) 

The resulting native SQL:

```sql
select distinct on (key)
     owner_id, hook_id, key, value_written as "value", ...
from hook_storage_change
where owner_id = :ownerId
  and hook_id = :hookId
  and key in (:keys)                                          -- arbitrarily large IN list
  and consensus_timestamp between :timestampLowerBound        -- arbitrarily wide range
                              and :timestampUpperBound
``` [4](#0-3) 

PostgreSQL's query planner abandons index-only or index-range scans when the `IN` list is large enough that a sequential scan becomes cheaper in its cost model. The `DISTINCT ON (key)` clause additionally forces a sort over all matching rows before the `LIMIT` (from `Pageable`) is applied, meaning the `limit=25` default does **not** bound the scan cost — only the output size.

**Why existing checks are insufficient:**

- The early-exit at line 93 only fires when `keysInRange.isEmpty() && requestHasKeys` — i.e., every supplied key is outside the key bounds. An attacker places at least one key inside the bounds to bypass this guard while still supplying thousands of additional keys.
- `Pageable` (limit) caps returned rows, not rows scanned or sort work.
- No rate limiting or query-cost guard is visible in the service layer. [5](#0-4) 

### Impact Explanation
A sustained stream of such requests (each with a large `keys` list and a wide timestamp range) can saturate DB CPU and I/O, degrading or denying service to all other mirror-node API consumers. Because the cost is borne by the database tier, not the application tier, horizontal scaling of the REST-Java service does not mitigate it. Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation
The API is publicly reachable by design (mirror node REST API). No credentials, tokens, or special roles are required. The attacker needs only to know the endpoint accepts a `keys` array and a `timestamp` range parameter — both are documented API features. The attack is trivially repeatable and scriptable with standard HTTP tooling.

### Recommendation

1. **Enforce a hard maximum on `keys` size** at the DTO or controller layer (e.g., `@Size(max = 100)` on `HookStorageRequest.keys`).
2. **Pass `keysInRange` instead of `keys`** to `findByKeyInAndTimestampBetween` (line 104) — this is also a correctness bug independent of the DoS concern.
3. **Enforce a maximum timestamp range width** (e.g., reject requests where `upperBound - lowerBound` exceeds a configured threshold).
4. Consider a DB-level statement timeout for this query class.

### Proof of Concept

```
# 1. Identify a valid hookId/ownerId pair (public data).
# 2. Craft a request with:
#    - timestamp range spanning the full history (e.g., 0 to Long.MAX_VALUE)
#    - keys[] containing N-1 out-of-range keys + 1 in-range key
#      (bypasses the keysInRange.isEmpty() guard while maximising IN clause)
#    - limit=1 (minimises response size, maximises server-side scan cost)

GET /api/v1/hooks/{ownerId}/{hookId}/storage
    ?timestamp=gte:0&timestamp=lte:9999999999999999999
    &key[]=<in_range_key>
    &key[]=<out_of_range_key_1>
    ...
    &key[]=<out_of_range_key_N>
    &limit=1

# Repeat in a tight loop from multiple clients.
# Observe DB CPU/IO spike; index scans replaced by sequential scans in pg_stat_statements.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L89-105)
```java
        final var keys = request.getKeys();
        final boolean requestHasKeys = !keys.isEmpty();
        final var keysInRange = request.getKeysInRange();

        if (keysInRange.isEmpty() && requestHasKeys) {
            return new HookStorageResult(ownerId, List.of());
        }

        final var timestamp = request.getTimestamp();
        final long timestampLowerBound = timestamp.getAdjustedLowerRangeValue();
        final long timestampUpperBound = timestamp.adjustUpperBound();

        List<HookStorage> changes;

        if (requestHasKeys) {
            changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
                    ownerId.getId(), hookId, keys, timestampLowerBound, timestampUpperBound, page);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L27-29)
```java
    @Builder.Default
    private final Collection<byte[]> keys = List.of();

```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L41-63)
```java
    @Query(nativeQuery = true, value = """
                    select distinct on (key)
                         owner_id,
                         hook_id,
                         key,
                         value_written       as "value",
                         consensus_timestamp as "modified_timestamp",
                         consensus_timestamp as "consensus_timestamp",
                         0                   as "created_timestamp",
                         (value_written is null or length(value_written) = 0) as "deleted"
                    from hook_storage_change
                    where owner_id = :ownerId
                      and hook_id = :hookId
                      and key in (:keys)
                      and consensus_timestamp between :timestampLowerBound and :timestampUpperBound
                    """)
    List<HookStorage> findByKeyInAndTimestampBetween(
            long ownerId,
            long hookId,
            Collection<byte[]> keys,
            long timestampLowerBound,
            long timestampUpperBound,
            Pageable pageable);
```
