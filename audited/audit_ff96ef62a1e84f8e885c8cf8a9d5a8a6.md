Looking at the actual code carefully across `Bound.java`, `NftAllowanceServiceImpl.java`, and `NumberRangeParameter.java`.

**Step 1 — Can `Long.MAX_VALUE` enter the system?** [1](#0-0) 

`getNumberValue` only rejects `value < 0`. `Long.MAX_VALUE` (9223372036854775807) is positive, so it passes validation and is stored as-is.

**Step 2 — Does `lowerBound++` overflow?** [2](#0-1) 

Java `long` arithmetic wraps silently. `Long.MAX_VALUE + 1 = Long.MIN_VALUE`. No `Math.addExact` or saturation guard is used here.

**Step 3 — Does the constructor range check catch it?** [3](#0-2) 

`adjustedLower = Long.MIN_VALUE`, `adjustedUpper = Long.MAX_VALUE` (no upper supplied). `Long.MIN_VALUE > Long.MAX_VALUE` is **false** → no exception, even when `primarySortField = true`.

**Step 4 — Does `checkOwnerSpenderParamValidity` catch it?** [4](#0-3) 

Same arithmetic: `tokenParams.getAdjustedLowerRangeValue()` returns `Long.MIN_VALUE`, `tokenParams.adjustUpperBound()` returns `Long.MAX_VALUE`. `Long.MIN_VALUE > Long.MAX_VALUE` is **false** → no exception thrown, query proceeds to the repository.

All four checks fail to detect the overflow. The vulnerability is real.

---

### Title
Integer Overflow in `Bound.getAdjustedLowerRangeValue()` Bypasses Range Validation, Leaking All NFT Allowances

### Summary
An unprivileged user can supply `GT:9223372036854775807` (Long.MAX_VALUE) as the `token.id` query parameter. The `lowerBound++` increment in `getAdjustedLowerRangeValue()` silently wraps to `Long.MIN_VALUE`, causing every subsequent range guard (`adjustedLower > adjustedUpper`) to evaluate to `false`. The malformed range is forwarded to the database unmodified, effectively removing the token-ID filter and returning all NFT allowances for the target account.

### Finding Description
**Code path:**
- `NumberRangeParameter.getNumberValue()` (`NumberRangeParameter.java:26-33`): only rejects negative values; `Long.MAX_VALUE` passes.
- `Bound.getAdjustedLowerRangeValue()` (`Bound.java:91-94`): `lowerBound = Long.MAX_VALUE; lowerBound++;` → wraps to `Long.MIN_VALUE` with no overflow guard.
- `Bound` constructor check (`Bound.java:56-60`): `Long.MIN_VALUE > Long.MAX_VALUE` → `false`; no exception even when `primarySortField = true`.
- `NftAllowanceServiceImpl.checkOwnerSpenderParamValidity()` (`NftAllowanceServiceImpl.java:41-44`): identical comparison, identical failure.

**Root cause:** The code assumes that a user-supplied `GT` value will never be `Long.MAX_VALUE`, so incrementing it is safe. Java's `long` arithmetic wraps silently; no `Math.addExact` or boundary check is present.

**Failed assumption:** The guard `adjustedLower > adjustedUpper` is intended to detect inverted ranges. After overflow, `adjustedLower = Long.MIN_VALUE`, which is always ≤ any `adjustedUpper`, so the guard is permanently defeated.

### Impact Explanation
The database query is issued with an effective lower bound of `Long.MIN_VALUE` for `token_id`. Since all valid Hedera entity IDs are non-negative, the condition `token_id >= Long.MIN_VALUE` matches every row, returning all NFT allowances for the queried account regardless of the intended token filter. This is an unauthenticated information-disclosure vulnerability: any caller can enumerate the complete NFT allowance set of any account by issuing a single crafted request.

### Likelihood Explanation
No authentication or privilege is required. The only precondition is knowing the API endpoint and the format of the `token.id` parameter (`gt:9223372036854775807`). The value is a well-known Java constant, trivially discoverable. The attack is deterministic and repeatable with a single HTTP GET request.

### Recommendation
1. **Clamp or reject boundary values before incrementing.** In `getAdjustedLowerRangeValue()`, replace `lowerBound++` with `Math.addExact(lowerBound, 1)` (throws `ArithmeticException` on overflow) or explicitly reject `Long.MAX_VALUE` when the operator is `GT`.
2. **Add an upper-bound input constraint** in `getNumberValue()` — e.g., reject values above a domain-specific maximum (Hedera entity IDs are bounded well below `Long.MAX_VALUE`).
3. Apply the same fix symmetrically to `adjustUpperBound()` (`lowerBound--` for `LT`) and `getInclusiveRangeValue()`, which contain the same pattern.

### Proof of Concept
```
GET /api/v1/accounts/{accountId}/allowances/nfts?token.id=gt:9223372036854775807
```
1. `NumberRangeParameter.valueOf("gt:9223372036854775807")` → `NumberRangeParameter(GT, 9223372036854775807L)` — passes `value < 0` check.
2. `Bound.getAdjustedLowerRangeValue()`: `lowerBound = 9223372036854775807L; lowerBound++` → `lowerBound = -9223372036854775808L` (Long.MIN_VALUE).
3. Constructor check: `-9223372036854775808L > 9223372036854775807L` → `false` → no exception.
4. `checkOwnerSpenderParamValidity`: same comparison → `false` → no exception.
5. Repository receives a query equivalent to `token_id >= Long.MIN_VALUE` — returns all NFT allowances for the account.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/NumberRangeParameter.java (L26-33)
```java
    private static long getNumberValue(String number) {
        var value = Long.parseLong(number);
        if (value < 0) {
            throw new IllegalArgumentException("Invalid range value");
        }

        return value;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L56-60)
```java
        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L86-97)
```java
    public long getAdjustedLowerRangeValue() {
        if (this.lower == null) {
            return 0;
        }

        long lowerBound = this.lower.value();
        if (this.lower.operator() == RangeOperator.GT) {
            lowerBound++;
        }

        return lowerBound;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L41-44)
```java
        if (!ownerOrSpenderParams.hasLowerAndUpper()
                && tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
        }
```
