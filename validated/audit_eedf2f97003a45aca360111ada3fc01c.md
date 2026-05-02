All five steps of the claim are confirmed by the actual code. Here is the audit report:

---

Audit Report

## Title
`lt:0x000...000` Underflow in `decrementByteArray()` Silently Converts Impossible Range to Full Key-Space Scan

## Summary
When a user supplies `key=lt:0x0000000000000000000000000000000000000000000000000000000000000000`, `SlotRangeParameter.valueOf()` calls `decrementByteArray()` on an all-zero 32-byte array. Apache Tuweni's `MutableBytes32.decrement()` wraps around to `0xFFFF...FFFF` with no exception. The resulting `SlotRangeParameter(LTE, 0xFFFF...FFFF)` is compared against `MAX_KEY_BYTES` (also `0xFFFF...FFFF`) in `hookStorageChangeRequest()`, the `< 0` guard is false, and `upperBound` is left at `MAX_KEY_BYTES`. The semantically impossible range silently becomes a full key-space scan.

## Finding Description

**Step 1 — Parameter parsing**

In `SlotRangeParameter.valueOf()`, when `operator == LT`, `getInclusiveValue` calls `decrementByteArray(bytes)` on the decoded hex value: [1](#0-0) 

For input `lt:0x000...000`, `bytes` is a 32-byte all-zero array.

**Step 2 — Underflow in `decrementByteArray`**

`BytesUtil.decrementByteArray` delegates directly to Tuweni's `MutableBytes32.decrement()` with no boundary check: [2](#0-1) 

Tuweni's `decrement()` on an all-zero array performs unsigned wraparound, returning `0xFFFF...FFFF`. No exception is thrown.

**Step 3 — `toInclusive()` conversion**

`SlotRangeParameter.valueOf()` calls `operator.toInclusive()` before constructing the record: [3](#0-2) 

`LT → LTE`, so the stored record is `SlotRangeParameter(LTE, 0xFFFF...FFFF)`.

**Step 4 — Bound selection guard fails**

In `hookStorageChangeRequest`, `hasUpperBound()` returns `true` for `LTE`: [4](#0-3) 

The guard that would tighten `upperBound` is: [5](#0-4) 

`Arrays.compareUnsigned(0xFF...FF, 0xFF...FF) < 0` evaluates to `false` (they are equal). `upperBound` remains `MAX_KEY_BYTES` (`0xFF...FF`).

**Step 5 — Full key-space scan executed**

The repository query uses the unconstrained bounds: [6](#0-5) 

This becomes `key BETWEEN 0x00...00 AND 0xFF...FF` — a full key-space scan for the given `ownerId`/`hookId`.

**Root cause**: `decrementByteArray` has no guard against being called on the minimum representable value (`0x00...00`). The `< 0` comparison in `hookStorageChangeRequest` cannot detect the wrapped value because it equals `MAX_KEY_BYTES`.

## Impact Explanation
The semantically correct result for `lt:MIN_KEY` is an empty result set. Instead, the server executes a full-range scan equivalent to providing no key filter at all. While the result set is bounded by `limit`, the database must evaluate `key BETWEEN MIN AND MAX` across all rows for the given `ownerId`/`hookId`. An attacker can repeatedly issue this single crafted request to force maximum-cost scans. Additionally, the response returns up to `limit` storage entries the caller did not intend to request.

## Likelihood Explanation
The exploit requires zero privileges — it is a plain unauthenticated GET request with a single crafted query parameter. The value `lt:0x000...000` is a natural boundary-test input. It is trivially repeatable and requires no special tooling. Any user who can reach the REST endpoint can trigger it.

## Recommendation
Add a boundary check in `getInclusiveValue` (or in `hookStorageChangeRequest`) before calling `decrementByteArray`. If the input bytes are all-zero and the operator is `LT`, the result is an empty set — return a sentinel value or throw a validated `IllegalArgumentException` that results in an empty response. For example:

```java
} else if (operator == RangeOperator.LT) {
    if (isAllZeros(bytes)) {
        throw new IllegalArgumentException("No key can be less than the minimum key 0x000...000");
    }
    return decrementByteArray(bytes);
}
```

Similarly, `incrementByteArray` should be guarded against overflow on `0xFF...FF` for the `GT` operator.

## Proof of Concept
```
GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage?key=lt:0x0000000000000000000000000000000000000000000000000000000000000000
```
Expected: empty result set (no key is less than the minimum).
Actual: full key-space scan returning up to `limit` storage entries for the given `ownerId`/`hookId`.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/RangeOperator.java (L52-57)
```java
    public RangeOperator toInclusive() {
        return switch (this) {
            case GT -> GTE;
            case LT -> LTE;
            default -> this;
        };
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/RangeParameter.java (L18-20)
```java
    default boolean hasUpperBound() {
        return operator() == RangeOperator.LT || operator() == RangeOperator.LTE;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L179-182)
```java
            } else if (key.hasUpperBound()) {
                if (Arrays.compareUnsigned(value, upperBound) < 0) {
                    upperBound = value;
                }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L26-30)
```java
                    where owner_id = :ownerId
                      and hook_id = :hookId
                      and key >= :keyLowerBound
                      and key <= :keyUpperBound
                      and consensus_timestamp between :timestampLowerBound and :timestampUpperBound
```
