### Title
Historical Hook Storage Query Bypasses Key Range Filter via Raw `keys` Instead of `keysInRange`

### Summary
In `HookServiceImpl.getHookStorageChange()`, when a historical query includes explicit keys, the code passes the raw `keys` collection to `HookStorageChangeRepository.findByKeyInAndTimestampBetween()` instead of the range-filtered `keysInRange`. The only guard — checking `keysInRange.isEmpty() && requestHasKeys` — is bypassed whenever at least one supplied key falls within the declared range, allowing all remaining out-of-range keys to be queried freely against the historical `hook_storage_change` table.

### Finding Description

**Non-historical path (correct):**
In `getHookStorage()`, line 72 computes `keysInRange` and line 78–79 passes it to the repository: [1](#0-0) 

**Historical path (buggy):**
In `getHookStorageChange()`, `keysInRange` is computed at line 91 but the guard at line 93 only short-circuits when `keysInRange` is entirely empty: [2](#0-1) 

When `requestHasKeys` is true and at least one key is in range, execution falls through to line 104, which passes the raw `keys` (not `keysInRange`) to the repository: [3](#0-2) 

The SQL query in `findByKeyInAndTimestampBetween` applies no key-range bounds — only `key in (:keys)`: [4](#0-3) 

`getKeysInRange()` correctly filters keys to `[keyLowerBound, keyUpperBound]`, but its output is never used in the historical branch: [5](#0-4) 

**Root cause:** The historical code path substitutes `keys` for `keysInRange` at line 104, making the range bounds declared by the caller (`keyLowerBound`/`keyUpperBound`) entirely ineffective when at least one key is in range.

### Impact Explanation
An unprivileged caller can retrieve historical `hook_storage_change` records for arbitrary storage keys belonging to any hook, as long as they include one legitimately in-range key to defeat the guard. This allows reading storage slot values at past timestamps that the caller was never authorized to access, violating the confidentiality of hook storage state. In a smart contract hook context, this leaks historical storage values across slot boundaries, which constitutes unintended smart contract behavior — a hook observes storage it should not see at a given timestamp.

### Likelihood Explanation
No special privilege is required. Any user who can issue a historical hook storage query (i.e., supply a `timestamp` parameter) can exploit this by crafting a `keys` list containing one in-range key and any number of out-of-range keys. The exploit is trivially repeatable and requires no race condition or timing dependency.

### Recommendation
Replace `keys` with `keysInRange` at line 104 of `HookServiceImpl.getHookStorageChange()`:

```java
// Before (buggy):
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keys, timestampLowerBound, timestampUpperBound, page);

// After (fixed):
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keysInRange, timestampLowerBound, timestampUpperBound, page);
```

This mirrors the correct behavior already present in the non-historical `getHookStorage()` path.

### Proof of Concept

**Preconditions:**
- Hook with `ownerId=1`, `hookId=42` exists.
- Storage key `0x0A` is within the declared range `[0x00, 0x0F]`.
- Storage key `0xFF` is outside the declared range and holds sensitive data in `hook_storage_change`.

**Steps:**
1. Issue a historical hook storage query with:
   - `keyLowerBound = 0x00`, `keyUpperBound = 0x0F`
   - `keys = [0x0A, 0xFF]`
   - `timestamp = <any valid historical timestamp>`
2. `getKeysInRange()` returns `[0x0A]` (non-empty → guard at line 93 does not fire).
3. `findByKeyInAndTimestampBetween` is called with `keys = [0x0A, 0xFF]`.
4. The SQL `key in (:keys)` matches both `0x0A` and `0xFF`.
5. Response includes the historical storage value for `0xFF`, which is outside the declared range and should not be accessible.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L72-79)
```java
        final var keysInRange = request.getKeysInRange();

        if (keysInRange.isEmpty()) {
            return new HookStorageResult(ownerId, List.of());
        }

        final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
                ownerId.getId(), request.getHookId(), keysInRange, page);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L89-95)
```java
        final var keys = request.getKeys();
        final boolean requestHasKeys = !keys.isEmpty();
        final var keysInRange = request.getKeysInRange();

        if (keysInRange.isEmpty() && requestHasKeys) {
            return new HookStorageResult(ownerId, List.of());
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L103-105)
```java
        if (requestHasKeys) {
            changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
                    ownerId.getId(), hookId, keys, timestampLowerBound, timestampUpperBound, page);
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
