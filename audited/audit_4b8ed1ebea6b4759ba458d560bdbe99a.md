### Title
Unbounded `keys` Collection in `getHookStorageChange()` Enables SQL IN-List DoS Against Historical Hashgraph Queries

### Summary
`HookServiceImpl.getHookStorageChange()` passes the caller-supplied, unfiltered `keys` collection directly to a native SQL query containing `key in (:keys)`. No size constraint exists on the `keys` field of `HookStorageRequest`, and the only early-exit guard is bypassed whenever at least one key falls within the declared range. An unprivileged attacker can submit a historical storage query with tens of thousands of keys, forcing the database to parse and execute a massive IN-list predicate, degrading or denying service for all legitimate historical Hashgraph queries.

### Finding Description

**Exact code path:**

`HookServiceImpl.getHookStorageChange()` — [1](#0-0) 

At line 89–91, both `keys` (original, unfiltered) and `keysInRange` (filtered to `[keyLowerBound, keyUpperBound]`) are computed: [2](#0-1) 

The only guard is at line 93–95 — it returns early **only if `keysInRange` is completely empty AND `requestHasKeys` is true**: [3](#0-2) 

If even a single key falls within the declared range, execution reaches line 103–105, where the **full, unfiltered `keys` collection** (not `keysInRange`) is forwarded to the repository: [4](#0-3) 

This is structurally inconsistent with the non-historical path, which correctly uses `keysInRange`: [5](#0-4) 

The repository method expands `:keys` directly into a native SQL `IN` clause with no server-side cap: [6](#0-5) 

The `HookStorageRequest` DTO has no `@Size`, `@Max`, or any other validation annotation on `keys`: [7](#0-6) 

**Root cause:** The `keys` field is an unbounded `Collection<byte[]>` with no cardinality constraint, and the service layer forwards the raw collection — not the range-filtered subset — to a native SQL query whose `IN` clause expands proportionally to the collection size.

**Failed assumption:** The code assumes callers supply a small, well-bounded set of keys. No enforcement of this assumption exists at the DTO, service, or repository layer.

### Impact Explanation

A single malicious HTTP request carrying, e.g., 100,000 byte-array keys with one valid in-range key will:
1. Force the JPA/Hibernate layer to serialize all 100,000 values into a SQL string, consuming heap on the application server.
2. Send a multi-megabyte SQL statement to the database, exhausting network and parse-tree resources.
3. Cause the database query planner to abandon index usage on `key`, falling back to sequential scans of `hook_storage_change`.
4. Block the database connection pool, preventing all concurrent legitimate historical queries from completing.

This directly impacts the integrity of historical Hashgraph state queries — the core audit trail of the mirror node — constituting a **high-severity availability impact** on a critical protocol component.

### Likelihood Explanation

- **No authentication required** — the question's own access model confirms unprivileged external access.
- **Trivially repeatable** — a single HTTP client can fire the request in a loop.
- **No rate-limiting or key-count cap** is visible anywhere in the service or DTO layer.
- The attacker needs only to know the API endpoint accepts a `keys` array and a `timestamp` range parameter (making the request historical), both of which are standard REST API parameters.

### Recommendation

1. **Enforce a maximum key count** on `HookStorageRequest.keys` using Bean Validation:
   ```java
   @Size(max = 100)
   private final Collection<byte[]> keys = List.of();
   ```
2. **Pass `keysInRange` instead of `keys`** to `findByKeyInAndTimestampBetween()` (line 104), matching the non-historical code path and eliminating the inconsistency.
3. **Add a server-side guard** in `getHookStorageChange()` that rejects or truncates requests where `keys.size()` exceeds a configured threshold before any repository call.
4. Consider **chunking large IN lists** at the repository layer if large key sets are a legitimate use case.

### Proof of Concept

**Preconditions:** API endpoint is publicly accessible; attacker knows a valid `ownerId`, `hookId`, and at least one valid key value.

**Steps:**

1. Construct a `HookStorageRequest` with:
   - `timestamp` set to any non-empty range (activates the historical path)
   - `keyLowerBound` / `keyUpperBound` spanning a wide range
   - `keys` = one valid in-range key + 99,999 arbitrary out-of-range-but-syntactically-valid keys

2. Submit the request to the hook storage endpoint.

3. **Trigger:** `getHookStorageChange()` computes `keysInRange` = `[validKey]` (non-empty), so the early-exit guard at line 93 does **not** fire. Execution reaches line 104 and passes all 100,000 keys to `findByKeyInAndTimestampBetween()`.

4. **Result:** The database receives a `SELECT ... WHERE key IN (val1, val2, ..., val100000) AND consensus_timestamp BETWEEN ...` query. Database CPU and memory spike; query planner degrades; connection pool exhausts; legitimate queries time out.

5. Repeat in a loop to sustain the denial of service.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L78-79)
```java
        final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
                ownerId.getId(), request.getHookId(), keysInRange, page);
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L27-29)
```java
    @Builder.Default
    private final Collection<byte[]> keys = List.of();

```
