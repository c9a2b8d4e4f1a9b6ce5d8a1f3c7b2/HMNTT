All code references in the claim have been verified against the actual source. Here is the audit result:

---

Audit Report

## Title
Silent Overwrite of Lower Bound When Duplicate GT Operators Supplied to Token Airdrop Endpoints

## Summary
`TokenAirdropsController.processRequest()` constructs a `Bound` for the primary sort field without ever calling `verifySingleOccurrence()`. When two GT (or GTE) parameters are supplied for `receiver.id` (on `/outstanding`) or `sender.id` (on `/pending`), the `Bound` constructor silently overwrites `lower` with the last-seen value while recording a cardinality of 2. No validation rejects this state, so the query executes against only the higher bound, silently returning a narrower result set.

## Finding Description
`TokenAirdropsController.java` line 71 accepts up to 2 `receiver.id` values via `@Size(max = 2)`: [1](#0-0) 

`processRequest()` at line 97 constructs the `Bound` with `primarySortField = true`: [2](#0-1) 

Inside the `Bound` constructor, for input `[gt:100, gt:200]`, the loop at lines 47–54 assigns `lower = gt:100` on the first iteration, then silently overwrites it with `lower = gt:200` on the second, while incrementing `cardinality[GT]` to 2: [3](#0-2) 

The only post-loop guard (lines 56–60) checks `adjustedLower > adjustedUpper`. With `lower = gt:200` and no upper bound (`Long.MAX_VALUE`), `201 > Long.MAX_VALUE` is false, so no exception is thrown: [4](#0-3) 

Back in `processRequest()` (lines 97–108), there is no call to `entityIdsBound.verifySingleOccurrence()`, `entityIdsBound.verifyUnsupported()`, or any equivalent: [5](#0-4) 

`TokenAirdropServiceImpl.getAirdrops()` also performs no validation — it immediately delegates to the repository: [6](#0-5) 

By contrast, `NftAllowanceServiceImpl.verifyRangeId()` correctly calls `ids.verifySingleOccurrence()`, which would throw `IllegalArgumentException` when GT cardinality exceeds 1: [7](#0-6) 

`verifySingleOccurrence()` exists and works correctly — it is simply never invoked for token airdrop requests: [8](#0-7) 

## Impact Explanation
The API returns HTTP 200 with a structurally valid but incomplete result set. Airdrops whose primary sort field value falls in the range `(lower_bound, higher_bound]` are silently excluded. A receiver enumerating claimable airdrops via `/outstanding` or `/pending` will receive an incomplete list with no indication of truncation, potentially missing airdrops before expiry.

## Likelihood Explanation
No authentication is required. The `@Size(max = 2)` annotation explicitly permits two values, making the input structurally valid from the framework's perspective. The bug is trivially triggered by any HTTP client and applies symmetrically to `sender.id` on `/pending`. It is fully deterministic and repeatable.

## Recommendation
Add a `verifySingleOccurrence()` call on the `entityIdsBound` in `processRequest()`, mirroring the pattern already used in `NftAllowanceServiceImpl.verifyRangeId()`. The same guard should be applied to the `serialNumbers` and `tokenIds` bounds for consistency. Alternatively, centralize this validation in `TokenAirdropServiceImpl.getAirdrops()` analogously to `NftAllowanceServiceImpl.checkOwnerSpenderParamValidity()`.

## Proof of Concept
```
GET /api/v1/accounts/0.0.1000/airdrops/outstanding
    ?receiver.id=gt:100&receiver.id=gt:200&limit=25
```
Expected behavior: reject with 400 (duplicate lower-bound operators).  
Actual behavior: HTTP 200, query executes as `receiver_id > 200`, silently omitting all airdrops with `receiver_id` in `(100, 200]`.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L71-71)
```java
            @RequestParam(name = RECEIVER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] receiverIds,
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L97-108)
```java
        var entityIdsBound = new Bound(entityIds, true, ACCOUNT_ID, type.getPrimaryField());
        var request = TokenAirdropRequest.builder()
                .accountId(id)
                .entityIds(entityIdsBound)
                .limit(limit)
                .order(order)
                .serialNumbers(new Bound(serialNumbers, false, SERIAL_NUMBER, TOKEN_AIRDROP.SERIAL_NUMBER))
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, TOKEN_AIRDROP.TOKEN_ID))
                .type(type)
                .build();

        var response = service.getAirdrops(request);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L47-54)
```java
        for (var param : params) {
            if (param.hasLowerBound()) {
                lower = param;
            } else if (param.hasUpperBound()) {
                upper = param;
            }
            cardinality.merge(param.operator(), 1, Math::addExact);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L155-159)
```java
    public void verifySingleOccurrence() {
        verifySingleOccurrence(RangeOperator.EQ);
        verifySingleOccurrence(RangeOperator.GT, RangeOperator.GTE);
        verifySingleOccurrence(RangeOperator.LT, RangeOperator.LTE);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
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
