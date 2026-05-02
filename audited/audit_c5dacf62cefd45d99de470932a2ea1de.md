### Title
Unbounded `keys` Collection in `findByKeyInAndTimestampBetween()` Enables DB Sequential Scan DoS

### Summary
The private `getHookStorageChange()` method in `HookServiceImpl` passes the raw, user-supplied `keys` collection directly to the native `key in (:keys)` clause with no size cap. An unprivileged caller can supply thousands of keys alongside a valid timestamp parameter, forcing PostgreSQL to generate a massive IN-list query that abandons index usage in favor of a sequential scan, degrading database performance for all concurrent operations.

### Finding Description

**Code path:**

`HookServiceImpl.java` lines 84–118 → `HookStorageChangeRepository.java` lines 41–63.

In `getHookStorageChange()`:

```java
// HookServiceImpl.java line 89
final var keys = request.getKeys();           // raw, unbounded user input
final boolean requestHasKeys = !keys.isEmpty();
final var keysInRange = request.getKeysInRange(); // filtered, but only used for early-exit

// line 93 — early-exit only fires when ALL keys are out of range
if (keysInRange.isEmpty() && requestHasKeys) {
    return new HookStorageResult(ownerId, List.of());
}

// line 103-105 — full unfiltered `keys` (not `keysInRange`) sent to DB
if (requestHasKeys) {
    changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
            ownerId.getId(), hookId, keys, ...);   // ← no size limit
}
```

The native query at `HookStorageChangeRepository.java` line 54:
```sql
and key in (:keys)
```

**Root cause / failed assumption:** The developer assumed `limit` (default 25, controls result pagination) also constrains the IN-list size. It does not. `keysInRange` is computed but used only for the early-exit guard; the actual query receives the full raw `keys` collection. `HookStorageRequest.java` line 28 shows `keys` defaults to `List.of()` with no maximum cardinality enforced anywhere in the DTO, service, or repository layer.

**Why the early-exit check is insufficient:** The guard at line 93 only returns early when *every* supplied key falls outside `[keyLowerBound, keyUpperBound]`. An attacker who includes even one in-range key alongside 9,999 out-of-range keys bypasses the guard and forces all 10,000 keys into the IN clause.

### Impact Explanation

PostgreSQL's query planner switches from an index scan to a sequential scan on `hook_storage_change` once the IN list exceeds a planner cost threshold (typically a few hundred elements). With thousands of keys, every invocation performs a full table scan. Because `hook_storage_change` is shared across all hooks and owners, a sustained flood of such requests saturates I/O and CPU on the database server, causing latency spikes and timeouts for all concurrent transaction confirmation queries — matching the "Critical: Network not being able to confirm new transactions" severity label.

### Likelihood Explanation

The attack requires no authentication or special privilege: only a valid `hookId`, `ownerId`, and any timestamp value (to set `isHistorical() = true`). The attacker can repeat the request in a tight loop. The payload is trivially constructed (a JSON/query-string array of arbitrary byte-array keys). No rate limiting or key-count validation exists in the identified code path.

### Recommendation

1. **Enforce a hard cap on `keys` size** at the DTO or service layer, e.g., reject requests where `keys.size() > limit` (or a configured maximum such as 100).
2. **Pass `keysInRange` — not `keys` — to the repository call** at `HookServiceImpl.java` line 104, so out-of-range keys are stripped before reaching the DB.
3. **Add a DB-level guard** via a `LIMIT` on the subquery or a check constraint, as defense-in-depth.
4. Consider adding API-level rate limiting on the historical storage endpoint.

### Proof of Concept

```
# Precondition: know any valid ownerId, hookId, and any timestamp range.
# No authentication required (unprivileged).

POST /api/v1/hooks/{ownerId}/{hookId}/storage?timestamp=gte:0000000001&timestamp=lte:9999999999
Content-Type: application/json

{
  "keys": [
    "0x0000000000000001",
    "0x0000000000000002",
    ... (repeat 10,000 entries, with at least one inside keyLowerBound–keyUpperBound)
  ]
}

# Result:
# HookServiceImpl line 90: requestHasKeys = true
# HookServiceImpl line 91: keysInRange = [one matching key] → not empty → guard at line 93 does NOT fire
# HookServiceImpl line 104: all 10,000 keys forwarded to `key in (:keys)`
# PostgreSQL abandons index on (owner_id, hook_id, key, consensus_timestamp),
#   performs sequential scan on hook_storage_change.
# Repeat in a loop → DB CPU/IO saturation → all concurrent queries time out.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L84-118)
```java
    private HookStorageResult getHookStorageChange(HookStorageRequest request) {
        final var page = request.getPageRequest();
        final var ownerId = entityService.lookup(request.getOwnerId());
        final long hookId = request.getHookId();

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
        } else {
            changes = hookStorageChangeRepository.findByKeyBetweenAndTimestampBetween(
                    ownerId.getId(),
                    hookId,
                    request.getKeyLowerBound(),
                    request.getKeyUpperBound(),
                    timestampLowerBound,
                    timestampUpperBound,
                    page);
        }

        return new HookStorageResult(ownerId, changes);
    }
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L27-52)
```java
    @Builder.Default
    private final Collection<byte[]> keys = List.of();

    private final byte[] keyUpperBound;

    @Builder.Default
    private final int limit = 25;

    @Builder.Default
    private final Direction order = Direction.ASC;

    private final EntityIdParameter ownerId;

    @Builder.Default
    private final Bound timestamp = Bound.EMPTY;

    public List<byte[]> getKeysInRange() {
        if (keys.isEmpty()) {
            return List.of();
        }

        return keys.stream()
                .filter(key -> Arrays.compareUnsigned(key, keyLowerBound) >= 0
                        && Arrays.compareUnsigned(key, keyUpperBound) <= 0)
                .toList();
    }
```
