### Title
`incrementByteArray` Overflow on All-0xFF Key Causes Full Storage Slot Disclosure

### Summary
When an unprivileged user supplies `key=gt:0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`, `SlotRangeParameter.getInclusiveValue()` calls `incrementByteArray()` on a 32-byte all-0xFF array. Apache Tuweni's `MutableBytes32.increment()` silently wraps around to all-0x00 instead of throwing. The resulting `lowerBound` is indistinguishable from `MIN_KEY_BYTES`, so the range filter is never tightened and the query returns every storage slot for the target hook.

### Finding Description

**Code path:**

1. `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage?key=gt:0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`

2. `SlotRangeParameter.valueOf()` — the regex `[0-9a-fA-F]{1,64}` accepts 64 hex `F`s; `leftPad` to 64 chars is a no-op. [1](#0-0) 

3. `getInclusiveValue(RangeOperator.GT, "FFFF…FFFF")` decodes to a 32-byte all-0xFF array and calls `incrementByteArray(bytes)`. [2](#0-1) 

4. `incrementByteArray` delegates to `MutableBytes32.wrap(bytes).increment().toArrayUnsafe()`. Tuweni's `increment()` on an all-0xFF `Bytes32` wraps silently to all-0x00 — no exception, no sentinel. [3](#0-2) 

5. Back in `hookStorageChangeRequest()`, `lowerBound` is initialised to `MIN_KEY_BYTES` (all-0x00). The guard `Arrays.compareUnsigned(value, lowerBound) > 0` evaluates `compareUnsigned(all-zeros, all-zeros) > 0` → `0 > 0` → **false**. `lowerBound` is never updated. [4](#0-3) 

6. `HookStorageRequest` is built with `keyLowerBound = all-zeros`, `keyUpperBound = MAX_KEY_BYTES` — the full key space — and the service returns every storage slot. [5](#0-4) 

**Root cause:** `incrementByteArray` has no overflow guard; the caller has no post-condition check that the incremented value is strictly greater than the original input.

**Failed assumption:** The code assumes `incrementByteArray(x) > x` always holds. For `x = 0xFF…FF` this is false.

### Impact Explanation
Any unauthenticated (or low-privilege) caller can enumerate the complete storage of any hook by issuing a single crafted GET request. Storage slots may contain sensitive contract state (balances, access-control mappings, private configuration). The endpoint is publicly reachable with no privilege requirement shown in the controller.

### Likelihood Explanation
The exploit requires zero authentication, zero cryptographic material, and a single HTTP GET request with a trivially constructed query parameter. It is deterministic and repeatable. Any attacker who reads the API documentation or fuzzes the `key` parameter will discover it.

### Recommendation
Add an overflow guard in `incrementByteArray` (or its callers) that detects the all-0xFF input and returns a sentinel indicating "no valid next value":

```java
public static Optional<byte[]> incrementByteArray(byte[] bytes) {
    // All-0xFF: no value exists above this; caller must treat as "impossible bound"
    boolean allFF = true;
    for (byte b : bytes) { if (b != (byte) 0xFF) { allFF = false; break; } }
    if (allFF) return Optional.empty();
    return Optional.of(MutableBytes32.wrap(bytes).increment().toArrayUnsafe());
}
```

In `hookStorageChangeRequest`, when `getInclusiveValue` returns the sentinel for a `GT` lower-bound, set a flag that forces the query to return an empty result set immediately (short-circuit before hitting the database).

Alternatively, after calling `incrementByteArray`, assert `Arrays.compareUnsigned(result, original) > 0`; if false, return an empty response.

### Proof of Concept

```
GET /api/v1/accounts/0.0.1234/hooks/1/storage
    ?key=gt:0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    &limit=100
```

Expected (correct) response: empty `storage` array — no key can be greater than the maximum 32-byte value.

Actual response: full list of up to `limit` storage slots starting from key `0x00…00`, i.e., the entire storage of hook `1` owned by account `0.0.1234`.

Repeat with increasing `limit` or pagination to extract all slots.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L19-20)
```java
    private static final Pattern SLOT_PATTERN =
            Pattern.compile("^(?:(?<op>eq|gt|gte|lt|lte):)?(?:0x)?(?<hex>[0-9a-fA-F]{1,64})$");
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/SlotRangeParameter.java (L41-46)
```java
    private static byte[] getInclusiveValue(RangeOperator operator, String hexValue) throws DecoderException {
        byte[] bytes = Hex.decodeHex(hexValue);

        if (operator == RangeOperator.GT) {
            return incrementByteArray(bytes);
        } else if (operator == RangeOperator.LT) {
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
