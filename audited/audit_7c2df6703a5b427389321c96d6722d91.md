### Title
`getHookStorageChange()` Passes Raw `keys` Instead of `keysInRange` to Repository, Bypassing Key-Range Filter

### Summary
In `HookServiceImpl.getHookStorageChange()`, when a request contains both a non-empty `keys` list and a timestamp `Bound`, the code correctly computes `keysInRange` (the subset of keys within `[keyLowerBound, keyUpperBound]`) but then passes the raw, unfiltered `keys` collection to `findByKeyInAndTimestampBetween()`. Because that SQL query has no key-range predicate — only `key in (:keys)` — any key outside the intended range that was included in the request is returned to the caller. The non-historical code path (`getHookStorage()`) correctly uses `keysInRange`; the historical path does not.

### Finding Description

**Exact location:** `rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java`, lines 84–118, function `getHookStorageChange()`.

**Root cause:**

```
// line 89 – raw user-supplied keys
final var keys = request.getKeys();
final boolean requestHasKeys = !keys.isEmpty();

// line 91 – correctly filtered subset
final var keysInRange = request.getKeysInRange();

// line 93 – guard: only bails out when ALL keys are out of range
if (keysInRange.isEmpty() && requestHasKeys) {
    return new HookStorageResult(ownerId, List.of());
}

// line 103-105 – BUG: passes raw `keys`, not `keysInRange`
if (requestHasKeys) {
    changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
            ownerId.getId(), hookId, keys,   // <-- should be keysInRange
            timestampLowerBound, timestampUpperBound, page);
}
```

`getKeysInRange()` (in `HookStorageRequest.java`, lines 43–52) filters the user-supplied keys to only those satisfying `keyLowerBound ≤ key ≤ keyUpperBound`. The guard on line 93 only short-circuits when `keysInRange` is completely empty. When at least one key is in range (so `keysInRange` is non-empty), the guard passes, but the subsequent repository call still uses the full `keys` collection.

The SQL query `findByKeyInAndTimestampBetween` (lines 41–63 of `HookStorageChangeRepository.java`) contains no key-range predicate:

```sql
where owner_id = :ownerId
  and hook_id  = :hookId
  and key in (:keys)                          -- no range check
  and consensus_timestamp between ...
```

So every key in the raw `keys` collection — including those outside `[keyLowerBound, keyUpperBound]` — is fetched from the database.

**Contrast with the non-historical path** (`getHookStorage()`, lines 72–79): it correctly passes `keysInRange` to the repository.

### Impact Explanation
An unauthenticated (or any) external caller can retrieve historical `HookStorage` change records for arbitrary keys belonging to any `(ownerId, hookId)` pair, as long as they know or can guess at least one key that falls within the declared key range. The attacker simply includes that in-range key (to pass the `keysInRange.isEmpty()` guard) alongside any number of out-of-range keys they wish to exfiltrate. This leaks historical state data that the key-range filter was designed to restrict.

### Likelihood Explanation
The exploit requires no privileges — only the ability to send an HTTP request to the mirror-node REST API with a `timestamp` parameter (making `isHistorical()` true) and a `keys` list. The condition is trivially satisfied: include one key inside the declared range and any number of keys outside it. The bug is deterministic and fully reproducible.

### Recommendation
Replace `keys` with `keysInRange` on line 104 of `HookServiceImpl.java`:

```java
// Before (buggy)
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keys, ...);

// After (fixed)
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keysInRange, ...);
```

This mirrors the correct behaviour already present in the non-historical `getHookStorage()` path.

### Proof of Concept
1. Identify a valid `(ownerId, hookId)` pair with known historical storage changes.
2. Choose `keyLowerBound = K1`, `keyUpperBound = K2` such that at least one legitimate key `Kin` satisfies `K1 ≤ Kin ≤ K2`.
3. Craft a `HookStorageRequest` with:
   - `timestamp` = any non-empty `Bound` (e.g., a valid consensus timestamp range) → `isHistorical()` returns `true`
   - `keys` = `[Kin, Kout1, Kout2, ...]` where `Kout*` are keys outside `[K1, K2]`
   - `keyLowerBound = K1`, `keyUpperBound = K2`
4. `getKeysInRange()` returns `[Kin]` (non-empty), so the guard at line 93 does **not** short-circuit.
5. `findByKeyInAndTimestampBetween()` is called with the full list `[Kin, Kout1, Kout2, ...]`.
6. The SQL query returns historical records for all supplied keys, including `Kout1`, `Kout2`, etc., which are outside the intended range. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L43-52)
```java
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
