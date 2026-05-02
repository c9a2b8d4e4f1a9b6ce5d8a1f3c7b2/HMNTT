### Title
Historical Hook Storage Query Bypasses Range Filter — Out-of-Range EQ Keys Leak Data

### Summary
In `HookServiceImpl.getHookStorageChange()`, the range-filtered key list (`keysInRange`) is used only as a guard check, but the actual database query is issued with the raw, unfiltered `keys` list. Any unprivileged caller who supplies at least one in-range EQ key alongside an out-of-range EQ key and a timestamp filter will receive storage-slot data for the out-of-range key, violating the intended range restriction.

### Finding Description
**Root cause — `HookServiceImpl.java` lines 89–105:**

`getHookStorageChange()` computes both `keys` (raw EQ list) and `keysInRange` (EQ keys filtered to `[keyLowerBound, keyUpperBound]`):

```java
final var keys = request.getKeys();                 // raw, unfiltered
final boolean requestHasKeys = !keys.isEmpty();
final var keysInRange = request.getKeysInRange();   // filtered

if (keysInRange.isEmpty() && requestHasKeys) {      // guard: only fires if ALL keys are out of range
    return new HookStorageResult(ownerId, List.of());
}
// ...
if (requestHasKeys) {
    changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
            ownerId.getId(), hookId, keys, ...);    // BUG: passes `keys`, not `keysInRange`
``` [1](#0-0) 

The guard at line 93 only short-circuits when **every** EQ key is out of range. As soon as one EQ key is in range, `keysInRange` is non-empty, the guard passes, and the query at line 104 is issued with the full `keys` collection — including keys that `getKeysInRange()` already determined to be outside the requested bounds.

**Contrast with the non-historical path** (lines 72–79), which correctly passes `keysInRange` to the repository:

```java
final var keysInRange = request.getKeysInRange();
if (keysInRange.isEmpty()) { return ...; }
hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
        ..., keysInRange, page);   // correct
``` [2](#0-1) 

**Controller side — `hookStorageChangeRequest()` lines 170–184:**

EQ keys are unconditionally appended to `keyFilters`; range operators only update `lowerBound`/`upperBound`. There is no pre-filtering of EQ keys against the range at construction time. [3](#0-2) 

**`getKeysInRange()` itself is correct** — it filters properly — but it is never used for the actual DB call in the historical path. [4](#0-3) 

### Impact Explanation
An unprivileged user can read historical hook storage values for arbitrary storage slots that the range filter was supposed to exclude. Because `ownerId` and `hookId` are path parameters with no authentication gate visible in the controller, any caller who knows (or enumerates) a valid `ownerId`/`hookId` pair can exploit this to exfiltrate historical state for slots outside the declared range. The leaked data is the full `value_written` column from `hook_storage_change`, which may contain sensitive contract state.

### Likelihood Explanation
The exploit requires only a standard HTTP GET request with no special privileges, tokens, or elevated access. The attacker needs a valid `ownerId`/`hookId` (both are enumerable from public hook listing endpoints) and must add a `timestamp` parameter to trigger the historical code path. The attack is trivially repeatable and requires no timing dependency or race condition.

### Recommendation
In `HookServiceImpl.getHookStorageChange()`, replace the `keys` variable with `keysInRange` in the repository call:

```java
// Before (line 104-105):
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keys, ...);

// After:
changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
        ownerId.getId(), hookId, keysInRange, ...);
```

This mirrors the already-correct non-historical path and ensures the range filter is enforced at the database level, not just as a guard check.

### Proof of Concept
**Preconditions:** A hook storage change exists for `ownerId=0.0.100`, `hookId=1`, at slot `key=0x0000...0001`, recorded at `timestamp=1000`.

**Request:**
```
GET /api/v1/accounts/0.0.100/hooks/1/storage
    ?key=eq:0000000000000000000000000000000000000000000000000000000000000001
    &key=eq:0000000000000000000000000000000000000000000000000000000000000099
    &key=gt:0000000000000000000000000000000000000000000000000000000000000002
    &timestamp=lte:9999999999
```

**Expected behavior:** Slot `0x0001` is below the `gt:0x0002` lower bound; only slot `0x0099` (if it exists) should be returned.

**Actual behavior:**
1. `hookStorageChangeRequest()` builds `keyFilters = [0x0001, 0x0099]`, `lowerBound = 0x0002`.
2. `getKeysInRange()` returns `[0x0099]` (non-empty), so the guard at line 93 does not fire.
3. `findByKeyInAndTimestampBetween` is called with `keys = [0x0001, 0x0099]`.
4. The response includes the historical value for slot `0x0001`, which should have been excluded.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L170-184)
```java
        for (final var key : keys) {
            final byte[] value = key.value();

            if (key.hasLowerBound()) {
                if (key.operator() == RangeOperator.EQ) {
                    keyFilters.add(value);
                } else if (Arrays.compareUnsigned(value, lowerBound) > 0) {
                    lowerBound = value;
                }
            } else if (key.hasUpperBound()) {
                if (Arrays.compareUnsigned(value, upperBound) < 0) {
                    upperBound = value;
                }
            }
        }
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
