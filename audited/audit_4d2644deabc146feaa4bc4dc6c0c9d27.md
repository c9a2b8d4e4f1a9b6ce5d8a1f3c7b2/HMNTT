### Title
Missing `verifySingleOccurrence()` Validation in Token Airdrop Endpoint Allows Duplicate Lower-Bound Range Operators

### Summary
The `getOutstandingAirdrops()` (and `getPendingAirdrops()`) endpoint in `TokenAirdropsController` accepts up to two `EntityIdRangeParameter` values for `receiver.id` (or `sender.id`) via `@Size(max=2)`, but never calls `verifySingleOccurrence()` on the resulting `Bound`. This allows an unprivileged user to supply two lower-bound operators of the same type (e.g., `receiver.id=gt:0&receiver.id=gt:1`), which silently passes all validation and reaches the database query layer. The `NftAllowanceServiceImpl` path correctly calls this check; the token airdrop path does not.

### Finding Description

**Controller — no validation beyond `@Size`:**

In `TokenAirdropsController.java` line 71, the parameter is declared as: [1](#0-0) 

`processRequest()` immediately wraps the raw array in a `Bound` and passes it to the service with no further validation: [2](#0-1) 

**Service — no validation at all:**

`TokenAirdropServiceImpl.getAirdrops()` calls only `entityService.lookup()` and `repository.findAll()`. There is no call to `verifySingleOccurrence()`, `verifyUnsupported()`, or `verifyEqualOrRange()`: [3](#0-2) 

**Contrast — NftAllowanceServiceImpl does call it:** [4](#0-3) 

**`Bound` constructor — last-write-wins, cardinality tracked but never checked:**

When two lower-bound parameters arrive, the loop silently overwrites `lower` with the last one and increments cardinality to 2 for `GT`: [5](#0-4) 

`verifySingleOccurrence()` would catch cardinality > 1 for the same operator group: [6](#0-5) 

But it is never invoked in the token airdrop code path, so the cardinality map is populated but never inspected.

**Root cause:** The `Bound` constructor silently resolves the conflict by keeping the last lower-bound parameter. The first parameter (`gt:0`) is discarded without error. The DB query executes with only `gt:1` as the effective lower bound, and the API returns HTTP 200 for input that should be rejected as malformed.

### Impact Explanation

The immediate behavioral impact is that the first of the two conflicting lower-bound parameters is silently dropped and the query executes with the last one. This is not a data-corruption or privilege-escalation issue, but it represents a broken contract: the API accepts and silently misinterprets input that the framework explicitly provides a guard (`verifySingleOccurrence`) to reject. An attacker can probe this inconsistency to understand internal parameter-resolution order, and the silent acceptance of malformed input violates the principle of least surprise and API contract integrity. Severity is **Low–Medium** (input validation bypass, no direct data impact).

### Likelihood Explanation

Any unauthenticated or unprivileged HTTP client can trigger this by appending a repeated query parameter (e.g., `?receiver.id=gt:0&receiver.id=gt:1`). No special knowledge, credentials, or tooling is required. The `@Size(max=2)` constraint is the only guard and it only limits count, not operator-type uniqueness. The exploit is trivially repeatable.

### Recommendation

Add the same validation that `NftAllowanceServiceImpl` applies. In `TokenAirdropServiceImpl.getAirdrops()` (or in a shared validation helper), call the following on each `Bound` before passing to the repository:

```java
bound.verifyUnsupported(RangeOperator.NE);
bound.verifySingleOccurrence();   // rejects gt:0 + gt:1
bound.verifyEqualOrRange();
```

Alternatively, centralise this validation in `Bound`'s constructor or in `processRequest()` in the controller so it cannot be omitted by any future service implementation.

### Proof of Concept

```
GET /api/v1/accounts/0.0.1234/airdrops/outstanding
    ?receiver.id=gt:0&receiver.id=gt:1
    &limit=25
```

**Expected:** HTTP 400 with message similar to `"Only one range operator from [GT, GTE] is allowed for the given parameter for receiver.id"`

**Actual:** HTTP 200; the first `gt:0` is silently discarded, the query runs with `receiver_account_id > 1` only, and results are returned as if the input were valid.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L71-74)
```java
            @RequestParam(name = RECEIVER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] receiverIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, receiverIds, limit, order, serialNumbers, tokenIds, OUTSTANDING);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L155-159)
```java
    public void verifySingleOccurrence() {
        verifySingleOccurrence(RangeOperator.EQ);
        verifySingleOccurrence(RangeOperator.GT, RangeOperator.GTE);
        verifySingleOccurrence(RangeOperator.LT, RangeOperator.LTE);
    }
```
