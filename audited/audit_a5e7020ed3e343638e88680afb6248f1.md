Let me look at the `Bound` constructor and the `primarySortField` parameter usage in tests to fully understand the validation flow.

### Title
Token Range Validity Check Bypassed When `ownerOrSpenderParams` Has Both Lower and Upper Bounds

### Summary
In `NftAllowanceServiceImpl.checkOwnerSpenderParamValidity()`, the token range validity check is guarded by `!ownerOrSpenderParams.hasLowerAndUpper()`. When a caller supplies both a lower and upper bound for `ownerOrSpenderId`, this guard evaluates to `false`, short-circuiting the `&&` and skipping the only service-layer check that would reject an impossible token range (lower > upper). The `Bound` constructor does not validate token ranges because `tokenIds` is always constructed with `primarySortField = false`. The repository then executes a query with an unsatisfiable predicate and silently returns empty results.

### Finding Description
**File:** `rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java`, lines 41–44

```java
if (!ownerOrSpenderParams.hasLowerAndUpper()
        && tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
    throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
}
```

**Root cause:** The condition `!ownerOrSpenderParams.hasLowerAndUpper()` is `false` whenever the caller provides both a GTE/GT and an LTE/LT for `account.id`. In that case the entire `&&` expression is `false` regardless of the token range, so the `IllegalArgumentException` is never thrown.

**Why the constructor does not save this:** `Bound.java` lines 56–60 perform the same adjusted-lower > adjusted-upper check, but only when `primarySortField == true`. Every call site that builds the `tokenIds` `Bound` passes `primarySortField = false` (confirmed in all test fixtures and the controller), so the constructor silently accepts an impossible token range.

**Exploit flow:**
1. Attacker sends a request with `account.id=gte:100&account.id=lte:200` → `ownerOrSpenderParams.hasLowerAndUpper()` returns `true`.
2. Attacker also sends `token.id=gte:9000&token.id=lte:1` → `getAdjustedLowerRangeValue()` = 9000, `adjustUpperBound()` = 1; 9000 > 1 is an impossible range.
3. `!ownerOrSpenderParams.hasLowerAndUpper()` = `false` → the check is skipped entirely.
4. `repository.findAll(request, id)` executes with the impossible token predicate.
5. The database returns zero rows; the API responds with an empty collection instead of a 400 error.

### Impact Explanation
Any unauthenticated caller can make the NFT allowance endpoint silently return an empty result set for a valid account that actually has allowances, by pairing a legitimate two-sided account range with an inverted token range. Downstream consumers (indexers, wallets, dApps) that rely on this endpoint receive incorrect data — specifically, missing records — without any indication that the query parameters were invalid. Severity is medium: no data is leaked or modified, but data integrity of exported records is compromised.

### Likelihood Explanation
No privileges are required. The parameters are ordinary HTTP query parameters accepted from any external user. The combination (two-sided account range + inverted token range) is trivially constructable and repeatable. Any attacker who reads the API documentation or fuzzes the endpoint can discover and exploit this.

### Recommendation
Remove the `!ownerOrSpenderParams.hasLowerAndUpper()` guard from the token range check, or move the check so it is unconditional:

```java
// Always validate the token range, regardless of ownerOrSpender bound shape
if (tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
    throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
}
```

Alternatively, pass `primarySortField = true` when constructing the `tokenIds` `Bound` so the constructor itself rejects impossible ranges at construction time, consistent with how `ownerOrSpenderIds` is validated.

### Proof of Concept
```
GET /api/v1/accounts/{validAccountId}/allowances/nfts
    ?account.id=gte:100&account.id=lte:200
    &token.id=gte:9000&token.id=lte:1
    &order=asc&limit=25
```

**Expected:** HTTP 400 "Invalid range provided for token.id"
**Actual:** HTTP 200 with an empty `allowances` array, even though the account has NFT allowances with token IDs between 1 and 9000.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L41-44)
```java
        if (!ownerOrSpenderParams.hasLowerAndUpper()
                && tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L130-132)
```java
    public boolean hasLowerAndUpper() {
        return lower != null && upper != null;
    }
```
