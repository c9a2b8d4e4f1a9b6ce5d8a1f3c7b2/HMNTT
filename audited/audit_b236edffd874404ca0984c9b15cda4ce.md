### Title
Byte Array Overflow in `incrementByteArray()` Causes `gt:0xFFFF...FFFF` to Return All Storage Slots

### Summary
When an unprivileged user supplies `key=gt:0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` to the hook storage endpoint, `SlotRangeParameter.getInclusiveValue()` calls `incrementByteArray()` on a 32-byte all-`0xFF` array. The Tuweni `MutableBytes32.increment()` wraps around to all-`0x00`, producing a value equal to `MIN_KEY_BYTES`. The subsequent `> 0` guard in `hookStorageChangeRequest()` then silently fails to update `lowerBound`, leaving it at `MIN_KEY_BYTES`, and the query returns every storage slot for the targeted hook instead of an empty result.

### Finding Description

**Exact code path:**

1. **`BytesUtil.incrementByteArray()`** — `rest-java/src/main/java/org/hiero/mirror/restjava/util/BytesUtil.java`, lines 13–15:
   ```java
   public static byte[] incrementByteArray(byte[] bytes) {
       return MutableBytes32.wrap(bytes).increment().toArrayUnsafe();
   }
   ```
   `MutableBytes32.increment()` (Apache Tuweni) performs unsigned big-endian increment with silent wrap-around. Input `[0xFF x 32]` → output `[0x00 x 32]`. No overflow detection or exception is raised. [1](#0-0) 

2. **`SlotRangeParameter.getInclusiveValue()`** — `rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java`, lines 41–50:
   ```java
   if (operator == RangeOperator.GT) {
       return incrementByteArray(bytes);   // wraps to [0x00 x 32] for all-0xFF input
   }
   ```
   The returned `value` is `[0x00 x 32]`. The operator is then converted to `GTE` via `operator.toInclusive()` (line 38), so the stored `SlotRangeParameter` is `(GTE, [0x00 x 32])`. [2](#0-1) 

3. **`hookStorageChangeRequest()`** — `rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java`, lines 167–184:
   ```java
   var lowerBound = MIN_KEY_BYTES;   // [0x00 x 32]
   ...
   } else if (Arrays.compareUnsigned(value, lowerBound) > 0) {
       lowerBound = value;
   }
   ```
   `value` is `[0x00 x 32]` (the overflowed result). `Arrays.compareUnsigned([0x00 x 32], [0x00 x 32])` returns `0`, which is **not** `> 0`. The guard fails silently; `lowerBound` is never updated and remains `MIN_KEY_BYTES`. [3](#0-2) 

4. **`HookServiceImpl.getHookStorage()`** — `rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java`, lines 65–69:
   ```java
   if (keys.isEmpty()) {
       final var hookStorage = hookStorageRepository
           .findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
               ownerId.getId(), request.getHookId(),
               request.getKeyLowerBound(),   // MIN_KEY_BYTES
               request.getKeyUpperBound(),   // MAX_KEY_BYTES
               page);
   ```
   Because no EQ keys were added, `keys.isEmpty()` is `true`. The repository is called with the full `[MIN, MAX]` range, returning **all** storage slots. [4](#0-3) 

**Root cause:** `incrementByteArray()` silently wraps on overflow; no sentinel/error is returned. The caller `getInclusiveValue()` has no post-condition check, and `hookStorageChangeRequest()` has no guard for the case where the incremented value equals `MIN_KEY_BYTES` (which is semantically impossible as a lower bound derived from `gt:MAX`). [1](#0-0) 

**Why existing checks are insufficient:**

- The `Arrays.compareUnsigned(value, lowerBound) > 0` guard at line 176 is designed to pick the *most restrictive* (highest) lower bound. It correctly rejects values ≤ current `lowerBound`, but it cannot distinguish between a legitimately supplied `gte:0x00...00` and an overflowed `gt:0xFF...FF`. Both produce the same byte array. [5](#0-4) 

- The `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` annotation on `keys` only limits the count of parameters, not their values. [6](#0-5) 

- The `SLOT_PATTERN` regex allows up to 64 hex characters, so `FFFF...FFFF` (64 chars) is a valid input. [7](#0-6) 

### Impact Explanation
An unauthenticated (or any low-privilege) caller can retrieve **all** storage slots for any `(ownerId, hookId)` pair by issuing a single crafted GET request. Hook storage may contain sensitive contract state. The attacker bypasses the intended key-range filter entirely, receiving up to `MAX_LIMIT` records per page and able to paginate through the full dataset. This is a direct information-disclosure vulnerability with no side-effects required. [8](#0-7) 

### Likelihood Explanation
The attack requires zero privileges, zero prior knowledge beyond a valid `ownerId`/`hookId` (both are enumerable from the public `/hooks` endpoint), and a single HTTP GET request. The payload is a well-formed string that passes all input validation. It is trivially repeatable and automatable. [9](#0-8) 

### Recommendation

1. **Detect overflow in `incrementByteArray()`**: Before incrementing, check whether the input is already `MAX_KEY_BYTES`. If so, return `null` or throw an `IllegalArgumentException` (e.g., `"gt operator applied to maximum key value yields empty result"`). [1](#0-0) 

2. **Handle the null/sentinel in `hookStorageChangeRequest()`**: If `getInclusiveValue()` signals overflow (null return or exception), immediately return an empty result — no storage slots can satisfy `key > MAX_KEY`. [10](#0-9) 

3. **Add a post-condition check**: After the loop, verify `Arrays.compareUnsigned(lowerBound, upperBound) <= 0`; if not, return an empty result. This also guards the symmetric `lt:0x00...00` case in `decrementByteArray()`. [11](#0-10) 

### Proof of Concept

**Preconditions:** Mirror node REST-Java service is running; a valid `ownerId` (e.g., `0.0.1234`) and `hookId` (e.g., `1`) with populated storage exist.

**Step 1 — Baseline (normal request, returns only slots ≥ 0x01):**
```
GET /api/v1/accounts/0.0.1234/hooks/1/storage?key=gte:0x0000000000000000000000000000000000000000000000000000000000000001
```
Returns slots with key ≥ `0x01...01`.

**Step 2 — Exploit (should return empty, actually returns all slots):**
```
GET /api/v1/accounts/0.0.1234/hooks/1/storage?key=gt:0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
```

**Trace:**
- `SlotRangeParameter.valueOf("gt:0xFFFF...FFFF")` → `incrementByteArray([0xFF x 32])` → `[0x00 x 32]`, operator stored as `GTE`
- In `hookStorageChangeRequest()`: `Arrays.compareUnsigned([0x00 x 32], MIN_KEY_BYTES) > 0` → `false` → `lowerBound` stays `MIN_KEY_BYTES`
- `HookServiceImpl` calls `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(ownerId, hookId, [0x00 x 32], [0xFF x 32], page)`
- **Result:** Full storage dump returned instead of empty list.

**Expected result:** `{ "storage": [] }` (no key can be greater than `0xFFFF...FFFF`)

**Actual result:** All storage slots for the hook are returned, up to the configured `limit` per page. [12](#0-11) [3](#0-2)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/util/BytesUtil.java (L13-15)
```java
    public static byte[] incrementByteArray(byte[] bytes) {
        return MutableBytes32.wrap(bytes).increment().toArrayUnsafe();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L19-20)
```java
    private static final Pattern SLOT_PATTERN =
            Pattern.compile("^(?:(?<op>eq|gt|gte|lt|lte):)?(?:0x)?(?<hex>[0-9a-fA-F]{1,64})$");
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L38-49)
```java
        return new SlotRangeParameter(operator.toInclusive(), getInclusiveValue(operator, hex));
    }

    private static byte[] getInclusiveValue(RangeOperator operator, String hexValue) throws DecoderException {
        byte[] bytes = Hex.decodeHex(hexValue);

        if (operator == RangeOperator.GT) {
            return incrementByteArray(bytes);
        } else if (operator == RangeOperator.LT) {
            return decrementByteArray(bytes);
        }
        return bytes;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L104-113)
```java
    @GetMapping("/{hookId}/storage")
    ResponseEntity<HooksStorageResponse> getHookStorage(
            @PathVariable EntityIdParameter ownerId,
            @PathVariable @Min(0) long hookId,
            @RequestParam(name = KEY, required = false, defaultValue = "") @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    List<SlotRangeParameter> keys,
            @RequestParam(name = TIMESTAMP, required = false, defaultValue = "") @Size(max = 2)
                    TimestampParameter[] timestamps,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Direction order) {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L167-197)
```java
        var lowerBound = MIN_KEY_BYTES;
        var upperBound = MAX_KEY_BYTES;

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

        final var bound = Bound.of(timestamps, TIMESTAMP, HookStorageChange.HOOK_STORAGE_CHANGE.CONSENSUS_TIMESTAMP);

        return HookStorageRequest.builder()
                .hookId(hookId)
                .keys(keyFilters)
                .limit(limit)
                .keyLowerBound(lowerBound)
                .keyUpperBound(upperBound)
                .order(order)
                .ownerId(ownerId)
                .timestamp(bound)
                .build();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L65-69)
```java
        if (keys.isEmpty()) {
            final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
                    ownerId.getId(), request.getHookId(), request.getKeyLowerBound(), request.getKeyUpperBound(), page);

            return new HookStorageResult(ownerId, hookStorage);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L16-17)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
            long ownerId, long hookId, byte[] fromKey, byte[] toKey, Pageable pageable);
```
