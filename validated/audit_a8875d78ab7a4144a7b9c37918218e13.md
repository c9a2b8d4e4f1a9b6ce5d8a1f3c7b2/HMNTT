All code references check out. Let me verify the full picture before writing the report.

Every claim in the submission is confirmed by the actual source:

1. **`Bound.java` lines 47–54**: The loop unconditionally overwrites `lower` on each iteration — confirmed. [1](#0-0) 

2. **`verifySingleOccurrence()` exists but is never called for airdrops** — `NftAllowanceServiceImpl` calls it via `verifyRangeId()` at line 58, `TokenAirdropServiceImpl.getAirdrops()` does not. [2](#0-1) [3](#0-2) 

3. **`@Size(max = 2)` on `senderIds`** allows two GTE params; `Bound` is constructed with `primarySortField = true` — confirmed. [4](#0-3) 

4. **The only guard** (`adjustedLower > adjustedUpper`) never fires when there is no upper bound because `adjustUpperBound()` returns `Long.MAX_VALUE` — confirmed. [5](#0-4) [6](#0-5) 

---

## Audit Report

## Title
Silent Overwrite of Lower Bound Allows Duplicate GTE Parameters to Omit Pending Airdrop Records

## Summary
`TokenAirdropServiceImpl.getAirdrops()` performs no input validation before forwarding the request to the repository. When a caller supplies two lower-bound operators for the same parameter (e.g., `sender.id=gte:0.0.1&sender.id=gte:0.0.1000`), the `Bound` constructor silently discards the first value and executes the query with only the second (higher) bound. All records for senders between the two GTE values are omitted from the response with no error signal.

## Finding Description

**Root cause — `Bound` constructor (`Bound.java` lines 47–54`):**

```java
for (var param : params) {
    if (param.hasLowerBound()) {
        lower = param;          // unconditional overwrite on every iteration
    } else if (param.hasUpperBound()) {
        upper = param;
    }
    cardinality.merge(param.operator(), 1, Math::addExact);
}
```

When `params = [GTE:1, GTE:1000]`, the loop assigns `lower = GTE:1` then immediately overwrites it with `lower = GTE:1000`. The `cardinality` map correctly records `{GTE: 2}`, but `lower` retains only the last value. [1](#0-0) 

**The guard that should catch this — `verifySingleOccurrence()` — is never called for airdrop requests:**

```java
public void verifySingleOccurrence() {
    verifySingleOccurrence(RangeOperator.EQ);
    verifySingleOccurrence(RangeOperator.GT, RangeOperator.GTE);
    verifySingleOccurrence(RangeOperator.LT, RangeOperator.LTE);
}
``` [7](#0-6) 

`NftAllowanceServiceImpl` correctly calls it via `verifyRangeId()`:

```java
private void verifyRangeId(Bound ids) {
    ids.verifyUnsupported(RangeOperator.NE);
    ids.verifySingleOccurrence();
    ids.verifyEqualOrRange();
}
``` [2](#0-1) 

`TokenAirdropServiceImpl.getAirdrops()` performs no such validation — it goes directly to the repository:

```java
public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
    var id = entityService.lookup(request.getAccountId());
    return repository.findAll(request, id);
}
``` [3](#0-2) 

**Why the existing range check does not catch it:**

The only guard in the `Bound` constructor is `adjustedLower > adjustedUpper`. With two GTE params and no upper bound, `adjustUpperBound()` returns `Long.MAX_VALUE`, so the check never fires regardless of the GTE values supplied. [5](#0-4) [6](#0-5) 

**Entry point — `@Size(max = 2)` explicitly permits two parameters:**

```java
@RequestParam(name = SENDER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] senderIds,
```

Spring's binding accepts both GTE values without error. The `Bound` is then constructed with `primarySortField = true` and the two-element array. [4](#0-3) 

## Impact Explanation
An external caller can craft a request that silently narrows the effective lower bound of the sender filter. All pending airdrop records for senders between the discarded (lower) GTE value and the surviving (higher) GTE value are omitted from the API response. No error is returned. Clients relying on this endpoint for auditing or reconciliation of pending airdrops will receive an incomplete, misleading result set. No data is written or deleted, but the mirror node's read-path correctness guarantee is violated for an unauthenticated caller.

## Likelihood Explanation
No authentication or privilege is required. The endpoint is public. The `@Size(max = 2)` annotation is the documented mechanism for supplying both a lower and upper bound (e.g., `sender.id=gte:X&sender.id=lte:Y`), so two-parameter usage is expected and explicitly permitted. A misconfigured client or a deliberate caller can trigger this with a single crafted HTTP GET request, repeatably and at will.

## Recommendation
Add the same validation that `NftAllowanceServiceImpl` applies via `verifyRangeId()` to the airdrop path. In `TokenAirdropServiceImpl.getAirdrops()` (or in `TokenAirdropsController.processRequest()` before the service call), call `verifySingleOccurrence()` on each `Bound` that is constructed from user-supplied parameters (`entityIds`, `tokenIds`, `serialNumbers`). This will cause the `cardinality` map — which already correctly counts duplicate operators — to throw an `IllegalArgumentException` (HTTP 400) when two lower-bound or two upper-bound operators are supplied for the same parameter, matching the behavior already enforced for NFT allowances.

## Proof of Concept

```
GET /api/v1/accounts/0.0.999/airdrops/pending?sender.id=gte:0.0.1&sender.id=gte:0.0.1000
```

**Expected behavior:** HTTP 400 — "Only one range operator from [GT, GTE] is allowed for the given parameter."

**Actual behavior:** HTTP 200 — query executes with `sender_account_id >= 1000` only. All pending airdrop records for senders `0.0.1` through `0.0.999` are silently omitted from the response.

To confirm, seed the database with pending airdrops for senders `0.0.500` and `0.0.1500` for receiver `0.0.999`. The above request returns only the `0.0.1500` record; the `0.0.500` record is absent with no indication of truncation.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L63-66)
```java
    public long adjustUpperBound() {
        if (this.upper == null) {
            return Long.MAX_VALUE;
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L56-60)
```java
    private void verifyRangeId(Bound ids) {
        ids.verifyUnsupported(RangeOperator.NE);
        ids.verifySingleOccurrence();
        ids.verifyEqualOrRange();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L82-97)
```java
            @RequestParam(name = SENDER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] senderIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, senderIds, limit, order, serialNumbers, tokenIds, PENDING);
    }

    @SuppressWarnings("java:S107")
    private TokenAirdropsResponse processRequest(
            EntityIdParameter id,
            EntityIdRangeParameter[] entityIds,
            int limit,
            Sort.Direction order,
            NumberRangeParameter[] serialNumbers,
            EntityIdRangeParameter[] tokenIds,
            AirdropRequestType type) {
        var entityIdsBound = new Bound(entityIds, true, ACCOUNT_ID, type.getPrimaryField());
```
