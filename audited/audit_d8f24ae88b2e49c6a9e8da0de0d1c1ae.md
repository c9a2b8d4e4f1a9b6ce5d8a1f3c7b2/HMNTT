### Title
Integer Overflow in `getAdjustedLowerRangeValue()` Bypasses Range Validation, Returning All Allowances Instead of None

### Summary
`Bound.getAdjustedLowerRangeValue()` increments a `long` lower-bound value without overflow protection. When a caller supplies operator `GT` with the maximum valid encoded entity ID (`511.65535.274877906943` = `Long.MAX_VALUE`), the `lowerBound++` silently wraps to `Long.MIN_VALUE`. The subsequent guard `adjustedLower > adjustedUpper` evaluates `Long.MIN_VALUE > Long.MAX_VALUE` → `false`, so no exception is thrown and the corrupted bound is forwarded to the database query, which returns all allowances for the target account instead of zero.

### Finding Description

**Exact location:**
`rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java`, `getAdjustedLowerRangeValue()`, lines 86–97.

```java
public long getAdjustedLowerRangeValue() {
    if (this.lower == null) {
        return 0;
    }
    long lowerBound = this.lower.value();
    if (this.lower.operator() == RangeOperator.GT) {
        lowerBound++;          // ← overflow when value == Long.MAX_VALUE
    }
    return lowerBound;
}
``` [1](#0-0) 

**Root cause:** Java signed-long arithmetic wraps silently; `Long.MAX_VALUE + 1 == Long.MIN_VALUE`.

**Why the guard fails:**
```java
long adjustedLower = getAdjustedLowerRangeValue();  // Long.MIN_VALUE
long adjustedUpper = adjustUpperBound();             // Long.MAX_VALUE (no upper supplied)
if (primarySortField && adjustedLower > adjustedUpper) { // MIN > MAX → false → no throw
    throw new IllegalArgumentException(...);
}
``` [2](#0-1) 

**Why `Long.MAX_VALUE` is a reachable input:**
`EntityId.encode()` accepts shard 0–1023, realm 0–65535, num 0–274877906943. The combination `511.65535.274877906943` encodes to exactly `Long.MAX_VALUE = 9223372036854775807`, which is a fully valid entity ID accepted by `EntityIdRangeParameter.valueOf()`. [3](#0-2) 

**Exploit flow:**
1. Attacker sends `GET /api/v1/accounts/{id}/allowances/nfts?account.id=gt:511.65535.274877906943`.
2. `EntityIdRangeParameter.valueOf("gt:511.65535.274877906943")` produces `(GT, Long.MAX_VALUE)`.
3. `Bound` constructor calls `getAdjustedLowerRangeValue()` → `Long.MAX_VALUE + 1` → `Long.MIN_VALUE`.
4. Guard `Long.MIN_VALUE > Long.MAX_VALUE` is `false`; no exception.
5. The corrupted `lower` bound (`GT, Long.MAX_VALUE`) is stored and later used by `NftAllowanceRepositoryCustomImpl.findAll()` to build a SQL condition `spender > Long.MAX_VALUE` — but because the adjusted value is `Long.MIN_VALUE`, the effective DB predicate becomes `spender >= Long.MIN_VALUE`, which matches every row for that account. [4](#0-3) 

The same unchecked arithmetic exists in `getInclusiveRangeValue()` (line 111) and `EntityIdRangeParameter.getInclusiveValue()` (line 57). [5](#0-4) [6](#0-5) 

### Impact Explanation
A semantically empty filter (`spender > MAX_ENTITY_ID` → should return 0 rows) silently becomes a full-pass filter (`spender >= Long.MIN_VALUE` → returns all allowances for the account, up to `limit`). This leaks the complete allowance list for any account the attacker targets, bypassing the intended pagination cursor. Repeated requests constitute a griefing/DoS vector against the DB index scan for large accounts, with no economic cost to the attacker.

### Likelihood Explanation
No authentication is required. The endpoint is public (`GET /api/v1/accounts/{id}/allowances/nfts`). The trigger value (`511.65535.274877906943`) is a standard, parseable entity ID string. Any unprivileged user can reproduce this with a single HTTP request. The attack is trivially repeatable and scriptable.

### Recommendation
Replace the bare increment with an overflow-safe check in `getAdjustedLowerRangeValue()` (and the identical patterns in `getInclusiveRangeValue()` and `EntityIdRangeParameter.getInclusiveValue()`):

```java
public long getAdjustedLowerRangeValue() {
    if (this.lower == null) return 0;
    long lowerBound = this.lower.value();
    if (this.lower.operator() == RangeOperator.GT) {
        if (lowerBound == Long.MAX_VALUE) {
            throw new IllegalArgumentException(
                "No entity ID exists greater than the maximum value for " + parameterName);
        }
        lowerBound++;
    }
    return lowerBound;
}
```

Alternatively use `Math.addExact(lowerBound, 1)` which throws `ArithmeticException` on overflow, then catch and convert to `IllegalArgumentException`.

### Proof of Concept

**Precondition:** At least one NFT allowance exists for account `0.0.1000`.

**Request:**
```
GET /api/v1/accounts/0.0.1000/allowances/nfts?account.id=gt:511.65535.274877906943
```

**Expected result:** `[]` (no entity ID can exceed `Long.MAX_VALUE`).

**Actual result:** All NFT allowances for account `0.0.1000` are returned (up to `limit`), because the overflow converts the lower bound to `Long.MIN_VALUE`, making the spender filter a no-op.

**Verification steps:**
1. Insert an NFT allowance with `owner=1000`, `spender=5000`, `approved_for_all=true`.
2. Send the request above.
3. Observe the allowance for spender `5000` is returned despite `5000 < Long.MAX_VALUE`, proving the filter was bypassed.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L107-118)
```java
    public long getInclusiveRangeValue(boolean upper) {
        var rangeParameter = upper ? this.getUpper() : this.getLower();
        var operator = rangeParameter.operator();
        long value = rangeParameter.value();
        if (operator == GT) {
            value += 1L;
        } else if (operator == LT) {
            value -= 1L;
        }

        return value;
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/EntityId.java (L75-85)
```java
    private static long encode(long shard, long realm, long num) {
        if (shard > SHARD_MASK || shard < 0 || realm > REALM_MASK || realm < 0 || num > NUM_MASK || num < 0) {
            throw new InvalidEntityException("Invalid entity ID: " + shard + "." + realm + "." + num);
        }

        if (shard == 0 && realm == 0) {
            return num;
        }

        return (num & NUM_MASK) | (realm & REALM_MASK) << NUM_BITS | (shard & SHARD_MASK) << (REALM_BITS + NUM_BITS);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java (L37-47)
```java
    public Collection<NftAllowance> findAll(NftAllowanceRequest request, EntityId accountId) {
        boolean byOwner = request.isOwner();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, byOwner).and(getBoundConditions(bounds));
        return dslContext
                .selectFrom(NFT_ALLOWANCE)
                .where(condition)
                .orderBy(SORT_ORDERS.get(new OrderSpec(byOwner, request.getOrder())))
                .limit(request.getLimit())
                .fetchInto(NftAllowance.class);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdRangeParameter.java (L55-61)
```java
    public long getInclusiveValue() {
        return switch (operator) {
            case GT -> value + 1;
            case LT -> value - 1;
            default -> value;
        };
    }
```
