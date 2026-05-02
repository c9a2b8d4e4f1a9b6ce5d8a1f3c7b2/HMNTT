All three root causes are confirmed by the actual code. Here is the audit report.

---

Audit Report

## Title
Token ID Range Inversion Bypass via Dual-Bound Account Parameter Silently Returns Zero Records

## Summary
In `NftAllowanceServiceImpl.checkOwnerSpenderParamValidity()`, the only guard that detects an inverted `token.id` range is wrapped in `!ownerOrSpenderParams.hasLowerAndUpper()`. When a caller supplies both a GTE and LTE on `account.id`, that guard is bypassed. Because the `Bound` constructor also skips its own inversion check for non-primary fields (`primarySortField=false`), the impossible predicate reaches the database and returns HTTP 200 with an empty list instead of HTTP 400.

## Finding Description

**Root cause 1 — `Bound` constructor skips inversion check for `primarySortField=false`:** [1](#0-0) 

The `adjustedLower > adjustedUpper` check only fires when `primarySortField == true`. `tokenIds` is always constructed with `primarySortField=false`: [2](#0-1) 

So `new Bound(tokenIds, false, TOKEN_ID, NFT_ALLOWANCE.TOKEN_ID)` with GTE:9999 and LTE:1 passes the constructor without error.

**Root cause 2 — service-level inversion check is gated on the wrong condition:** [3](#0-2) 

The only service-level guard that would catch an inverted token range is wrapped in `!ownerOrSpenderParams.hasLowerAndUpper()`. When the caller supplies both GTE and LTE on `account.id`, `hasLowerAndUpper()` returns `true`, the negation is `false`, and the block is never entered. [4](#0-3) 

**Root cause 3 — `verifyRangeId()` does not check inversion:** [5](#0-4) 

`verifyUnsupported`, `verifySingleOccurrence`, and `verifyEqualOrRange` only check operator type and count, not whether the lower bound value exceeds the upper bound value. [6](#0-5) 

**The two remaining checks in `checkOwnerSpenderParamValidity` also do not catch this case:** [7](#0-6) 

With `account.id=gte:100&account.id=lte:200`, `ownerOrSpenderParams` has both GTE and LTE, so `getCardinality(EQ, LTE) > 0` and `getCardinality(EQ, GTE) > 0` — both conditions evaluate to false and neither exception is thrown.

**The inverted predicate reaches the repository unchanged:** [8](#0-7) 

## Impact Explanation
Any caller can craft a request that silently returns an empty result set instead of a 400 error. The API returns HTTP 200 with `"allowances": []`, making the missing data invisible to consumers. Downstream systems that rely on this endpoint to enumerate NFT allowances will silently receive no records, potentially causing incorrect state assumptions or missed data.

## Likelihood Explanation
No authentication or special privilege is required. The parameters are standard query-string inputs on a public REST endpoint. The condition is trivially reproducible by any user who reads the API documentation and supplies two `account.id` operators alongside an inverted `token.id` range. It is fully repeatable and deterministic.

## Recommendation
Remove the `!ownerOrSpenderParams.hasLowerAndUpper()` guard from the token range inversion check in `NftAllowanceServiceImpl.checkOwnerSpenderParamValidity()`. The inversion check for `tokenParams` should be unconditional:

```java
// Before (buggy):
if (!ownerOrSpenderParams.hasLowerAndUpper()
        && tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
    throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
}

// After (fixed):
if (tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
    throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
}
```

Alternatively, the `Bound` constructor's inversion check should be applied regardless of `primarySortField`, so that all `Bound` instances with both a lower and upper value are validated at construction time.

## Proof of Concept

```
GET /api/v1/accounts/0.0.500/allowances/nfts
    ?account.id=gte:100
    &account.id=lte:200
    &token.id=gte:9999
    &token.id=lte:1
```

**Step-by-step bypass:**
1. `ownerOrSpenderIds` Bound is constructed with `primarySortField=true`, lower=GTE:100, upper=LTE:200 — valid range, passes constructor.
2. `tokenIds` Bound is constructed with `primarySortField=false`, lower=GTE:9999, upper=LTE:1 — constructor skips inversion check because `primarySortField=false`. [9](#0-8) 
3. `checkOwnerSpenderParamValidity` is called. `ownerOrSpenderParams.hasLowerAndUpper()` = `true` → the inversion guard is skipped. [3](#0-2) 
4. `verifyRangeId(tokenIds)` passes — no NE operator, no duplicate operators, no EQ+range mix.
5. The two remaining checks pass because `account.id` has both GTE and LTE. [7](#0-6) 
6. Repository executes: `WHERE owner = 500 AND approved_for_all = true AND spender >= 100 AND spender <= 200 AND token_id >= 9999 AND token_id <= 1` → 0 rows.
7. Response: HTTP 200 `{"allowances": [], "links": {"next": null}}`.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L56-60)
```java
        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L130-132)
```java
    public boolean hasLowerAndUpper() {
        return lower != null && upper != null;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L148-167)
```java
    public void verifyUnsupported(RangeOperator unsupportedOperator) {
        if (getCardinality(unsupportedOperator) > 0) {
            throw new IllegalArgumentException(
                    String.format("Unsupported range operator %s for %s", unsupportedOperator, parameterName));
        }
    }

    public void verifySingleOccurrence() {
        verifySingleOccurrence(RangeOperator.EQ);
        verifySingleOccurrence(RangeOperator.GT, RangeOperator.GTE);
        verifySingleOccurrence(RangeOperator.LT, RangeOperator.LTE);
    }

    public void verifyEqualOrRange() {
        if (this.getCardinality(RangeOperator.EQ) == 1
                && (this.getCardinality(RangeOperator.GT, RangeOperator.GTE) != 0
                        || this.getCardinality(RangeOperator.LT, RangeOperator.LTE) != 0)) {
            throw new IllegalArgumentException("Can't support both range and equal for %s".formatted(parameterName));
        }
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L72-72)
```java
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, NFT_ALLOWANCE.TOKEN_ID))
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L41-44)
```java
        if (!ownerOrSpenderParams.hasLowerAndUpper()
                && tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L46-53)
```java
        if (tokenParams.getCardinality(RangeOperator.LT, RangeOperator.LTE) > 0
                && ownerOrSpenderParams.getCardinality(RangeOperator.EQ, RangeOperator.LTE) == 0) {
            throw new IllegalArgumentException("Requires the presence of an lte or eq account.id parameter");
        }
        if (tokenParams.getCardinality(RangeOperator.GT, RangeOperator.GTE) > 0
                && ownerOrSpenderParams.getCardinality(RangeOperator.EQ, RangeOperator.GTE) == 0) {
            throw new IllegalArgumentException("Requires the presence of an gte or eq account.id parameter");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L56-60)
```java
    private void verifyRangeId(Bound ids) {
        ids.verifyUnsupported(RangeOperator.NE);
        ids.verifySingleOccurrence();
        ids.verifyEqualOrRange();
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
