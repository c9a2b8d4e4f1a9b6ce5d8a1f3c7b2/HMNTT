### Title
Silent Overwrite of `upper` Bound Allows Duplicate LTE `serialNumber` Parameters to Bypass Validation in Token Airdrop Queries

### Summary
The `Bound` constructor in `rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java` silently overwrites the `upper` field when two upper-bound parameters (e.g., two `lte:` operators) are supplied, because `verifySingleOccurrence()` is never called in the token airdrop code path. An unprivileged external user can supply `serialNumber=lte:100&serialNumber=lte:200`, causing the constructor to silently discard the first value and use the last, producing an incorrect query without any error or rejection.

### Finding Description

**Exact code path:**

In `Bound.java` lines 47–54, the constructor iterates over all params and unconditionally overwrites `upper` for every upper-bound param:

```java
for (var param : params) {
    if (param.hasLowerBound()) {
        lower = param;
    } else if (param.hasUpperBound()) {
        upper = param;   // silently overwritten on second LTE param
    }
    cardinality.merge(param.operator(), 1, Math::addExact);
}
``` [1](#0-0) 

The `cardinality` map correctly records `{LTE: 2}`, but the constructor never calls `verifySingleOccurrence()` to act on it. [2](#0-1) 

**Root cause — `verifySingleOccurrence()` is never called for token airdrop serial numbers:**

`verifySingleOccurrence()` is only called in `NftAllowanceServiceImpl.java` (one call site in the entire codebase). The token airdrop service path is:

- `TokenAirdropsController.processRequest()` (line 103) constructs `new Bound(serialNumbers, false, SERIAL_NUMBER, TOKEN_AIRDROP.SERIAL_NUMBER)` and passes it directly to the service. [3](#0-2) 

- `TokenAirdropServiceImpl.getAirdrops()` (lines 19–22) performs zero validation on the bounds before forwarding to the repository. [4](#0-3) 

**Why the existing `@Size(max = 2)` check is insufficient:**

The controller accepts up to 2 `serialNumber` values via `@Size(max = 2)`: [5](#0-4) 

This only limits the array length to 2. It does not prevent both values from being LTE operators. The `@Size` annotation is a Bean Validation constraint on array length, not on operator uniqueness.

**Exploit flow:**

1. User sends: `GET /api/v1/accounts/{id}/airdrops/outstanding?serialNumber=lte:1&serialNumber=lte:999999999`
2. Spring binds both into `NumberRangeParameter[] serialNumbers` (length 2, passes `@Size(max=2)`).
3. `new Bound(serialNumbers, false, SERIAL_NUMBER, ...)` is called.
4. Loop iteration 1: `upper = lte:1`, `cardinality = {LTE:1}`.
5. Loop iteration 2: `upper = lte:999999999` (overwrites silently), `cardinality = {LTE:2}`.
6. No exception is thrown. The constructed `Bound` has `upper = lte:999999999`.
7. The repository query uses `serial_number <= 999999999` instead of `serial_number <= 1`, returning a much broader result set than the first parameter intended.

### Impact Explanation
The query silently uses the last-supplied LTE value as the upper bound, ignoring the first. This means an attacker can widen the effective filter range for `serialNumber` beyond what a legitimate user would expect, causing the API to return results outside the intended range. While the result set is bounded by the `limit` parameter (capped by `@Max(MAX_LIMIT)`), the incorrect upper bound means the query scans and returns data that should have been excluded, leading to information disclosure of airdrop records outside the intended serial number range. The behavior is silent — no error is returned to the caller, making it undetectable from the response.

### Likelihood Explanation
This requires no authentication, no special privileges, and no brute force. Any external user who reads the API documentation (which documents `serialNumber` as accepting up to 2 range parameters) can trivially craft this request. The `@Size(max=2)` annotation explicitly advertises that two values are accepted. The attack is fully repeatable and deterministic.

### Recommendation
Call `verifySingleOccurrence()` on the `serialNumbers` bound in the token airdrop service or controller before the request is processed, mirroring the pattern already used in `NftAllowanceServiceImpl`. Alternatively, move the `verifySingleOccurrence()` call into the `Bound` constructor itself so it is enforced universally, rather than relying on each call site to remember to invoke it.

```java
// In TokenAirdropServiceImpl.getAirdrops() or TokenAirdropsController.processRequest():
request.getSerialNumbers().verifySingleOccurrence();
```

Or enforce it in the `Bound` constructor directly after the loop (lines 56–60). [6](#0-5) 

### Proof of Concept

```
GET /api/v1/accounts/0.0.12345/airdrops/outstanding?serialNumber=lte:1&serialNumber=lte:999999999&limit=100
```

**Expected behavior:** Request rejected with `400 Bad Request` ("Only one range operator from [LT, LTE] is allowed").

**Actual behavior:** Request succeeds. The query uses `serial_number <= 999999999`, returning up to 100 airdrop records with any serial number up to 999999999, instead of being restricted to serial numbers ≤ 1. No error is returned.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L39-61)
```java
    public Bound(RangeParameter<Long>[] params, boolean primarySortField, String parameterName, Field<Long> field) {
        this.field = field;
        this.parameterName = parameterName;

        if (ArrayUtils.isEmpty(params)) {
            return;
        }

        for (var param : params) {
            if (param.hasLowerBound()) {
                lower = param;
            } else if (param.hasUpperBound()) {
                upper = param;
            }
            cardinality.merge(param.operator(), 1, Math::addExact);
        }

        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
        }
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L72-73)
```java
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L103-104)
```java
                .serialNumbers(new Bound(serialNumbers, false, SERIAL_NUMBER, TOKEN_AIRDROP.SERIAL_NUMBER))
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, TOKEN_AIRDROP.TOKEN_ID))
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
    }
```
