All code references have been verified. Here is the audit result:

---

Audit Report

## Title
`incrementByteArray()` Overflow on Max Key Causes Full Storage Scan Instead of Empty Result

## Summary
When a caller supplies `key=gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` to the hook storage endpoint, `SlotRangeParameter.valueOf()` calls `BytesUtil.incrementByteArray()` on the 32-byte maximum value. Tuweni's `MutableBytes32.increment()` silently wraps around to `0x0000...0000`. The resulting `SlotRangeParameter` carries `operator=GTE` and `value=0x0000...0000`, which is identical to `MIN_KEY_BYTES`. The comparison in `hookStorageChangeRequest()` evaluates `0 > 0 = false`, so `lowerBound` is never updated, and the query is issued over the full key range `[0x0000...0000, 0xFFFF...FFFF]`, returning all hook storage slots instead of an empty result.

## Finding Description

**Step 1 — Input parsing in `SlotRangeParameter.valueOf()`** [1](#0-0) 

For input `gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`:
- `operator = GT`, `hex = "ffff...ffff"` (64 chars)
- `operator.toInclusive()` → `GTE` (confirmed in `RangeOperator.toInclusive()`)
- `getInclusiveValue(GT, hex)` → calls `incrementByteArray(bytes)` [2](#0-1) 

**Step 2 — Silent overflow in `BytesUtil.incrementByteArray()`** [3](#0-2) 

`MutableBytes32.wrap([0xFF×32]).increment()` performs fixed-width 256-bit arithmetic with no overflow check. `0xFFFF...FFFF + 1` wraps to `0x0000...0000`. No exception is thrown. The constructed `SlotRangeParameter` is `(operator=GTE, value=[0x00×32])`.

**Step 3 — Failed bound update in `hookStorageChangeRequest()`** [4](#0-3) 

- `lowerBound` is initialized to `MIN_KEY_BYTES = [0x00×32]`
- `key.hasLowerBound()` → `true` (GTE satisfies this)
- `key.operator() == EQ` → `false`
- `Arrays.compareUnsigned([0x00×32], [0x00×32]) > 0` → `0 > 0` → **`false`**
- The `lowerBound = value` assignment is **never reached**

`lowerBound` stays `[0x00×32]`, `upperBound` stays `[0xFF×32]`, `keyFilters` is empty.

**Step 4 — Full-range query issued** [5](#0-4) 

Because `keys.isEmpty()` is `true`, `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse` is called with bounds `[0x0000...0000, 0xFFFF...FFFF]` — the entire key space — returning all hook storage slots for the given `(ownerId, hookId)`.

## Impact Explanation
Any caller can retrieve all non-deleted hook storage slots for any `(ownerId, hookId)` pair, up to `MAX_LIMIT` per page, and paginate through the full dataset. The intended semantic of `gt:max_value` is an empty result (no key can exceed the maximum 32-byte value). Instead, the full storage is disclosed. This constitutes unauthorized data disclosure of all hook storage state for any account/hook combination reachable via the API.

## Likelihood Explanation
No authentication or privileges are required. The endpoint is a standard HTTP GET at `/api/v1/accounts/{ownerId}/hooks/{hookId}/storage`. The input `gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` passes all existing validation:
- The regex `^(?:(?<op>eq|gt|gte|lt|lte):)?(?:0x)?(?<hex>[0-9a-fA-F]{1,64})$` matches [6](#0-5) 

- The `@Size(max = MAX_REPEATED_QUERY_PARAMETERS)` constraint on the `keys` list is satisfied with a single parameter [7](#0-6) 

The attack requires a single HTTP request, no special tooling, and is trivially repeatable.

## Recommendation
The overflow must be detected before the wrapped value is used. Two complementary fixes are appropriate:

1. **In `SlotRangeParameter.getInclusiveValue()`**: Before calling `incrementByteArray`, check whether the input bytes are already the 32-byte maximum value. If so, throw an `IllegalArgumentException` (resulting in a `400 Bad Request`), since no key can be strictly greater than the maximum.

2. **In `BytesUtil.incrementByteArray()`**: Detect overflow (i.e., all input bytes are `0xFF`) and throw an `ArithmeticException` or `IllegalArgumentException` rather than silently wrapping.

A defensive secondary check in `hookStorageChangeRequest()` — detecting when the computed `lowerBound` equals `MIN_KEY_BYTES` after processing a `GTE` filter whose original operator was `GT` — would also prevent the full-scan fallback, but the root fix belongs at the parsing layer. [8](#0-7) 

## Proof of Concept

```
GET /api/v1/accounts/0.0.1234/hooks/1/storage?key=gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

**Trace:**
1. `SlotRangeParameter.valueOf("gt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")`
2. `getInclusiveValue(GT, "ffff...ffff")` → `incrementByteArray([0xFF×32])` → `[0x00×32]`
3. Constructed: `SlotRangeParameter(GTE, [0x00×32])`
4. In `hookStorageChangeRequest()`: `Arrays.compareUnsigned([0x00×32], MIN_KEY_BYTES=[0x00×32]) > 0` → `false` → `lowerBound` unchanged
5. `HookServiceImpl.getHookStorage()` calls `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(ownerId, hookId, [0x00×32], [0xFF×32], page)`
6. **All hook storage slots for `(ownerId=1234, hookId=1)` are returned.**

Expected behavior: empty result set (no key is strictly greater than `0xFFFF...FFFF`).

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L19-20)
```java
    private static final Pattern SLOT_PATTERN =
            Pattern.compile("^(?:(?<op>eq|gt|gte|lt|lte):)?(?:0x)?(?<hex>[0-9a-fA-F]{1,64})$");
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L35-38)
```java
        final var operator = (operatorGroup == null) ? RangeOperator.EQ : RangeOperator.of(operatorGroup);
        final var hex = StringUtils.leftPad(hexGroup, 64, '0');

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/RangeOperator.java (L52-58)
```java
    public RangeOperator toInclusive() {
        return switch (this) {
            case GT -> GTE;
            case LT -> LTE;
            default -> this;
        };
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/util/BytesUtil.java (L13-15)
```java
    public static byte[] incrementByteArray(byte[] bytes) {
        return MutableBytes32.wrap(bytes).increment().toArrayUnsafe();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L108-109)
```java
            @RequestParam(name = KEY, required = false, defaultValue = "") @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    List<SlotRangeParameter> keys,
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L167-178)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L65-69)
```java
        if (keys.isEmpty()) {
            final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
                    ownerId.getId(), request.getHookId(), request.getKeyLowerBound(), request.getKeyUpperBound(), page);

            return new HookStorageResult(ownerId, hookStorage);
```
