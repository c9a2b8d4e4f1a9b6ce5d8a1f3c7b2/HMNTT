### Title
Byte Array Underflow in `SlotRangeParameter` Causes `lt:0x0000...0000` to Return All Storage Slots Instead of None

### Summary
When an unprivileged user supplies `key=lt:0x0000000000000000000000000000000000000000000000000000000000000000`, `decrementByteArray()` is called on a 32-byte all-zero array, which wraps around to all-0xFF via Tuweni's `MutableBytes32.decrement()`. The resulting value equals the default `MAX_KEY_BYTES` (all 0xFF), so the upper-bound comparison check in `hookStorageChangeRequest()` silently discards the filter, and the query returns every storage slot instead of none.

### Finding Description

**Exact code path:**

1. **`SlotRangeParameter.valueOf()`** — [1](#0-0) 
   - Input `lt:0x0000...0000` → `operator = LT`, `hex = "000...0"` (64 zeros)
   - `operator.toInclusive()` converts `LT` → `LTE` for the stored record operator
   - `getInclusiveValue(LT, hex)` is called with the **original** `LT` operator

2. **`getInclusiveValue()`** — [2](#0-1) 
   - `operator == RangeOperator.LT` → calls `decrementByteArray(all_zeros_32_bytes)`

3. **`decrementByteArray()`** — [3](#0-2) 
   - `MutableBytes32.wrap(all_zeros).decrement()` wraps around to all-0xFF (unsigned underflow)
   - Returns a 32-byte array of `0xFF`

4. **`hookStorageChangeRequest()`** — [4](#0-3) 
   - `var upperBound = MAX_KEY_BYTES;` — initialized to all-0xFF
   - `key.hasUpperBound()` → `true` (stored operator is `LTE`)
   - Guard: `Arrays.compareUnsigned(value, upperBound) < 0` — both `value` and `upperBound` are all-0xFF → comparison returns `0`, condition is **false**
   - `upperBound` is **never updated**; it stays as `MAX_KEY_BYTES` (all 0xFF)

**Root cause:** No underflow guard exists in `decrementByteArray()` or in `getInclusiveValue()`. The semantic meaning of `lt:0x0000...0000` ("no key can satisfy this") is lost because the wrapped-around value is indistinguishable from the default maximum bound.

### Impact Explanation
The query is built with `keyLowerBound = MIN_KEY_BYTES` (all 0x00) and `keyUpperBound = MAX_KEY_BYTES` (all 0xFF) — identical to a request with **no key filter at all**. [5](#0-4)  Every storage slot for the targeted hook/owner is returned, constituting a full information-disclosure bypass of the intended filter. An attacker can enumerate all contract storage state for any hook without needing any privilege.

### Likelihood Explanation
The endpoint is a public `GET` API requiring no authentication. [6](#0-5)  The payload is a single, trivially crafted query parameter. No special knowledge, credentials, or rate-limit bypass is needed. The attack is fully repeatable and deterministic.

### Recommendation
Add an explicit underflow guard in `getInclusiveValue()` (or in `decrementByteArray()`): if the input is already the minimum value (all-zero 32-byte array), the `lt:` operator is unsatisfiable and should either throw an `IllegalArgumentException` (rejected at parse time) or return a sentinel that the controller recognizes as "empty result set." For example:

```java
} else if (operator == RangeOperator.LT) {
    if (Arrays.equals(bytes, new byte[32])) {
        throw new IllegalArgumentException(
            "lt:0x0000...0000 is unsatisfiable: no key is less than the minimum");
    }
    return decrementByteArray(bytes);
}
```

Alternatively, add a post-loop check in `hookStorageChangeRequest()`: if `Arrays.compareUnsigned(lowerBound, upperBound) > 0`, return an empty result immediately.

### Proof of Concept

```
GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage
    ?key=lt:0x0000000000000000000000000000000000000000000000000000000000000000
    &limit=100
```

**Expected:** 0 results (no key is less than the minimum).  
**Actual:** Up to `limit` storage slots returned, identical to an unfiltered request — full storage disclosure for the targeted hook.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/util/BytesUtil.java (L17-19)
```java
    public static byte[] decrementByteArray(byte[] bytes) {
        return MutableBytes32.wrap(bytes).decrement().toArrayUnsafe();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L104-115)
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

        final var request = hookStorageChangeRequest(ownerId, hookId, keys, timestamps, limit, order);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L188-197)
```java
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
