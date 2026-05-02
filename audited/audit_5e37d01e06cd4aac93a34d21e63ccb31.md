### Title
`incrementByteArray()` Overflow on Max Key Causes Full Storage Scan Instead of Empty Result

### Summary
When an unprivileged user supplies `key=gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`, `SlotRangeParameter.valueOf()` calls `incrementByteArray()` on the 32-byte maximum value. `MutableBytes32.increment()` wraps around to `0x0000...0000`. The subsequent comparison in `hookStorageChangeRequest()` fails to detect this wrapped value as a new lower bound, leaving `lowerBound` at `MIN_KEY_BYTES` (also `0x0000...0000`), causing the query to return all hook storage slots instead of an empty result.

### Finding Description

**Exact code path:**

1. **Input parsing** — `SlotRangeParameter.valueOf("gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")`: [1](#0-0) 
   - `operator = GT`, `bytes = [0xFF × 32]`
   - Calls `incrementByteArray(bytes)` → `MutableBytes32.wrap(bytes).increment().toArrayUnsafe()`

2. **Overflow** — `BytesUtil.incrementByteArray()`: [2](#0-1) 
   Tuweni's `MutableBytes32.increment()` performs fixed-width 256-bit arithmetic with silent wrap-around. `0xFFFF...FFFF + 1 = 0x0000...0000`. No exception is thrown.

3. **Stored parameter** — `SlotRangeParameter` is constructed with `operator=GTE` (via `GT.toInclusive()`) and `value=0x0000...0000`. [3](#0-2) 

4. **Bound comparison fails** — In `hookStorageChangeRequest()`: [4](#0-3) 
   - `lowerBound` starts as `MIN_KEY_BYTES = 0x0000...0000`
   - `key.hasLowerBound()` → `true` (GTE is a lower bound)
   - `key.operator() == EQ` → `false`
   - `Arrays.compareUnsigned(0x0000...0000, 0x0000...0000) > 0` → **`0 > 0` = `false`**
   - The `lowerBound = value` assignment is **never reached**

5. **Full-range query issued** — `lowerBound` stays `MIN_KEY_BYTES`, `upperBound` stays `MAX_KEY_BYTES`, `keyFilters` is empty: [5](#0-4) 
   `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse` is called with `[0x0000...0000, 0xFFFF...FFFF]` — the entire key space.

### Impact Explanation

Any unauthenticated caller can retrieve all hook storage slots for any `(ownerId, hookId)` pair, up to `MAX_LIMIT` per page, and paginate through the full dataset. The intended semantic of `gt:max_value` is an empty result (no key can exceed the maximum). Instead, the full storage is exposed. This is an unauthorized data disclosure of all hook storage state.

### Likelihood Explanation

No privileges are required. The endpoint is a standard HTTP GET. The input `gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` passes all existing validation (regex, `@Size`). The attack is trivially repeatable, requires no special tooling, and is a single HTTP request. Any user who can reach the API can exploit it.

### Recommendation

1. **Guard `incrementByteArray` against overflow**: Before calling `MutableBytes32.increment()`, check if the input equals `MAX_KEY_BYTES`. If so, return a sentinel or throw `IllegalArgumentException("Key value too large for gt operator")`.

2. **Alternatively, detect the wrap in `hookStorageChangeRequest`**: After computing the inclusive value for a `GT` key, verify that the result is strictly greater than the original input. If `Arrays.compareUnsigned(result, original) <= 0`, the overflow occurred — treat it as an impossible lower bound and return an empty result immediately.

3. **Add a test case** for `SlotRangeParameter.valueOf("gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")` asserting it either throws or produces an empty query result.

### Proof of Concept

```
GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage?key=gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

**Expected**: `{ "storage": [] }` (no key can be greater than the maximum)

**Actual**: Returns all storage slots for the given `(ownerId, hookId)`, paginated up to `MAX_LIMIT`.

Trace:
1. `SlotRangeParameter.valueOf("gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")`
2. → `incrementByteArray([0xFF×32])` → `[0x00×32]` (Tuweni wrap-around)
3. → `SlotRangeParameter(GTE, [0x00×32])`
4. → `Arrays.compareUnsigned([0x00×32], MIN_KEY_BYTES=[0x00×32]) > 0` → `false` → `lowerBound` unchanged
5. → `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(ownerId, hookId, [0x00×32], [0xFF×32], page)` → all rows returned

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L38-38)
```java
        return new SlotRangeParameter(operator.toInclusive(), getInclusiveValue(operator, hex));
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L41-50)
```java
    private static byte[] getInclusiveValue(RangeOperator operator, String hexValue) throws DecoderException {
        byte[] bytes = Hex.decodeHex(hexValue);

        if (operator == RangeOperator.GT) {
            return incrementByteArray(bytes);
        } else if (operator == RangeOperator.LT) {
            return decrementByteArray(bytes);
        }
        return bytes;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/util/BytesUtil.java (L13-15)
```java
    public static byte[] incrementByteArray(byte[] bytes) {
        return MutableBytes32.wrap(bytes).increment().toArrayUnsafe();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L167-183)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L65-69)
```java
        if (keys.isEmpty()) {
            final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
                    ownerId.getId(), request.getHookId(), request.getKeyLowerBound(), request.getKeyUpperBound(), page);

            return new HookStorageResult(ownerId, hookStorage);
```
