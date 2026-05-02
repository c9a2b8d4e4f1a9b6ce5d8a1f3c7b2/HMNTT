### Title
Unauthenticated Three-Bound Query Amplification in `getAirdrops()` Enables Griefing via Elevated DB Load

### Summary
Any unauthenticated caller can supply all three optional filter parameters (`receiver.id`/`sender.id`, `token.id`, `serialnumber`) simultaneously to the `/api/v1/accounts/{id}/airdrops/outstanding` or `/pending` endpoints. This causes `TokenAirdropRequest.getBounds()` to return a three-element `Bound` list, which `JooqRepository.getBoundConditions()` processes recursively, generating a significantly more complex nested OR/AND SQL predicate compared to the single-bound baseline. No rate limiting exists on the `rest-java` service layer.

### Finding Description
**Code path:**

`TokenAirdropsController.getOutstandingAirdrops()` / `getPendingAirdrops()`
→ `processRequest()` builds a `TokenAirdropRequest` with all three `Bound` fields populated
→ `TokenAirdropServiceImpl.getAirdrops()` calls `repository.findAll(request, id)`
→ `TokenAirdropRepositoryCustomImpl.findAll()` calls `request.getBounds()` then `getBoundConditions(bounds)`

**Root cause — `TokenAirdropRequest.getBounds()` (lines 65–77):**

```java
public List<Bound> getBounds() {
    var primaryBound = !entityIds.isEmpty() ? entityIds : tokenIds;
    if (primaryBound.isEmpty()) {
        return List.of(serialNumbers);
    }
    var secondaryBound = !tokenIds.isEmpty() ? tokenIds : serialNumbers;
    if (secondaryBound.isEmpty()) {
        return List.of(primaryBound);
    }
    return List.of(primaryBound, secondaryBound, serialNumbers); // ← three-element path
}
```

When `entityIds`, `tokenIds`, and `serialNumbers` are all non-empty, the method unconditionally returns a three-element list.

**`JooqRepository.getBoundConditions()` (lines 67–92)** processes this list recursively, producing a nested SQL predicate of the form:

```sql
(receiver_id = A AND (
    (token_id = C AND serial_number >= E) OR token_id > C
))
OR (receiver_id > A AND receiver_id < B)
OR (receiver_id = B AND (
    token_id < D OR (token_id = D AND serial_number <= F)
))
```

This is structurally more expensive than the single-bound case (`receiver_id >= A`) because the planner must evaluate three disjunctive branches, each with nested sub-conditions, rather than a simple range scan.

**Why existing checks are insufficient:**

- `@Size(max = 2)` on each parameter array only prevents more than 2 values per field; it does not prevent all three fields from being supplied simultaneously.
- `@Max(MAX_LIMIT)` caps the result set size but does not reduce the WHERE-clause evaluation cost.
- No rate limiting, authentication, or per-IP throttling exists in the `rest-java` service (the throttle infrastructure found in the codebase is confined to the `web3` module).

### Impact Explanation
An attacker can continuously issue maximally-parameterized requests (all three bound fields, each with both a lower and upper range value — 6 query parameters total) to force the database to evaluate the most expensive query variant on every call. Over many concurrent requests, this elevates CPU and I/O load on the shared PostgreSQL instance, potentially degrading response times for all users of the mirror node API. No funds or on-chain state are affected; the impact is availability degradation (griefing).

### Likelihood Explanation
The exploit requires zero privileges, zero tokens, and zero on-chain interaction. The HTTP endpoint is publicly reachable. The attacker needs only to craft a URL with six query parameters and repeat it at high frequency. This is trivially scriptable and repeatable from any internet-connected host.

### Recommendation
1. **Rate limiting:** Apply a per-IP or per-client request rate limit at the `rest-java` layer (e.g., via a Spring `HandlerInterceptor` or an API gateway) for the airdrop endpoints.
2. **Query complexity cap:** In `TokenAirdropRequest.getBounds()`, consider rejecting or downgrading requests that supply all three bound dimensions simultaneously when the primary bound is a range (not an equality), since the three-bound range case is the most expensive variant.
3. **Validation gate:** Add a validator that rejects requests where `serialNumbers` is non-empty unless `entityIds` or `tokenIds` is also constrained to an equality (`EQ`) operator, matching the intended pagination use-case rather than open-ended range scans across all three dimensions.

### Proof of Concept
```
# Trigger the three-bound, full-range query path — no authentication required
GET /api/v1/accounts/0.0.1000/airdrops/outstanding
    ?receiver.id=gte:0.0.1
    &receiver.id=lte:0.0.999999999
    &token.id=gte:0.0.1
    &token.id=lte:0.0.999999999
    &serialnumber=gte:1
    &serialnumber=lte:9999999999

# Repeat in a tight loop from multiple clients to amplify DB load.
# Each request causes getBounds() to return List.of(entityIds, tokenIds, serialNumbers)
# and getBoundConditions() to generate the full three-level nested OR predicate.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/TokenAirdropRequest.java (L65-77)
```java
    public List<Bound> getBounds() {
        var primaryBound = !entityIds.isEmpty() ? entityIds : tokenIds;
        if (primaryBound.isEmpty()) {
            return List.of(serialNumbers);
        }

        var secondaryBound = !tokenIds.isEmpty() ? tokenIds : serialNumbers;
        if (secondaryBound.isEmpty()) {
            return List.of(primaryBound);
        }

        return List.of(primaryBound, secondaryBound, serialNumbers);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/JooqRepository.java (L67-92)
```java
    private Condition getBoundConditions(List<Bound> bounds, boolean lowerProcessed, boolean upperProcessed) {
        if (bounds == null || bounds.isEmpty()) {
            return noCondition();
        }

        var primary = bounds.getFirst();
        if (bounds.size() == 1) {
            return getCondition(primary);
        }

        var secondaryBounds = bounds.subList(1, bounds.size());
        if (!lowerProcessed) {
            for (var bound : secondaryBounds) {
                // Only secondary bounds should be adjusted
                bound.adjustUpperRange();
            }
        }

        // Lower conditions need to be discovered before upper conditions because the methods involved update the
        // primary bound
        var lowerCondition = getOuterCondition(primary, secondaryBounds, false, lowerProcessed);
        var middleCondition = getMiddleCondition(primary, secondaryBounds);
        var upperCondition = getOuterCondition(primary, secondaryBounds, true, upperProcessed);

        return lowerCondition.or(middleCondition).or(upperCondition);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TokenAirdropRepositoryCustomImpl.java (L58-72)
```java
    public Collection<TokenAirdrop> findAll(TokenAirdropRequest request, EntityId accountId) {
        var type = request.getType();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, type.getBaseField())
                .and(getBoundConditions(bounds))
                .and(TOKEN_AIRDROP.STATE.eq(AirdropState.PENDING));

        var order = SORT_ORDERS.getOrDefault(type, Map.of()).get(request.getOrder());
        return dslContext
                .selectFrom(TOKEN_AIRDROP)
                .where(condition)
                .orderBy(order)
                .limit(request.getLimit())
                .fetchInto(TokenAirdrop.class);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L66-75)
```java
    @GetMapping(value = "/outstanding")
    TokenAirdropsResponse getOutstandingAirdrops(
            @PathVariable EntityIdParameter id,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(name = RECEIVER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] receiverIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, receiverIds, limit, order, serialNumbers, tokenIds, OUTSTANDING);
    }
```
