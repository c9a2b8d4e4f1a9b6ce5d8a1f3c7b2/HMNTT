### Title
Unauthenticated Repeated Wide-Range Descending-Order NFT Allowance Queries Enable DB Resource Exhaustion

### Summary
The `getNftAllowances()` endpoint in `AllowancesController` accepts fully open-ended range parameters (`account.id=gte:0.0.1`, `token.id=gt:0.0.1`) combined with `order=desc` and `limit=100` from any unauthenticated caller. The `rest-java` module has no rate limiting on this endpoint, and the repository executes a reverse B-tree index scan with no query cost guard. An attacker can flood the endpoint with the maximally expensive query combination indefinitely, exhausting database CPU and I/O.

### Finding Description

**Exact code path:**

`AllowancesController.java` lines 57–83 accepts all four attacker-controlled parameters without restriction beyond `@Max(100)` on `limit` and `@Size(max=2)` on the array parameters:

```
@RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,   // 100 allowed
@RequestParam(defaultValue = "asc") Sort.Direction order,                           // desc allowed
@RequestParam(name = ACCOUNT_ID, required = false) @Size(max = 2) ...accountIds,   // gte:0.0.1 allowed
@RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) ...tokenIds        // gt:0.0.1 allowed
```

`NftAllowanceServiceImpl.java` lines 33–53 (`checkOwnerSpenderParamValidity`) validates only operator *combinations*, not range *width*. The combination `account.id=gte:0.0.1` + `token.id=gt:0.0.1` passes all checks at lines 46–52 because GTE is present for `account.id` when GT is present for `token.id`.

`NftAllowanceRepositoryCustomImpl.java` lines 37–47 then executes:

```sql
SELECT * FROM nft_allowance
WHERE owner = ? AND approved_for_all = true
  AND spender >= 1 AND token_id > 1
ORDER BY spender DESC, token_id DESC
LIMIT 100
```

The `SORT_ORDERS` map at line 29 maps `(owner=true, DESC)` to `SPENDER.desc(), TOKEN_ID.desc()`, forcing a reverse B-tree scan across the entire table for the given owner.

**Why checks fail:**
- `@Max(MAX_LIMIT)` caps rows returned but does not cap scan cost.
- `@Size(max=2)` caps parameter count but not range width.
- The service validator only enforces operator pairing rules, not range bounds.
- The `rest-java` module contains only `LoggingFilter` and `MetricsFilter` — no rate-limiting filter exists for this endpoint (unlike the `web3` module which has `ThrottleConfiguration`/`ThrottleManagerImpl`).

### Impact Explanation
Repeated execution of this query forces the PostgreSQL engine to perform a full reverse index scan on `nft_allowance` for every active owner account targeted. With no per-IP or per-endpoint rate limit in `rest-java`, a single attacker thread can saturate database CPU and I/O, degrading or denying service to all legitimate mirror node API consumers. The impact is scoped to the mirror node infrastructure (no on-chain economic damage), consistent with the Medium/griefing classification.

### Likelihood Explanation
No authentication, registration, or special privilege is required. The attack requires only knowledge of a valid account ID (publicly discoverable via other mirror node APIs) and a standard HTTP client. The request is stateless and trivially parallelizable across multiple source IPs. The attacker bears zero cost.

### Recommendation
1. **Add rate limiting to `rest-java`**: Implement a per-IP or global token-bucket rate limiter (mirroring the `web3` `ThrottleConfiguration`) applied to all `rest-java` endpoints, with a tighter limit for the `/allowances/nfts` endpoint.
2. **Enforce a DB statement timeout**: Set `statement_timeout` on the database role used by `rest-java` to bound worst-case query duration.
3. **Restrict open-ended descending range queries**: In `NftAllowanceServiceImpl.checkOwnerSpenderParamValidity`, reject or warn when `order=desc` is combined with a lower-bound-only range (no upper bound on `account.id`), or require an upper bound when `order=desc` is requested.
4. **Add a minimum lower bound**: Reject `account.id=gte:0.0.1` (entity num ≤ some threshold) as it effectively means "scan everything."

### Proof of Concept

```bash
# Attacker script — no credentials needed
ACCOUNT="0.0.500000"   # any valid account with NFT allowances
URL="https://<mirror-node>/api/v1/accounts/${ACCOUNT}/allowances/nfts"
PARAMS="?limit=100&order=desc&account.id=gte:0.0.1&token.id=gt:0.0.1"

while true; do
  curl -s "${URL}${PARAMS}" -o /dev/null &
done
```

1. Substitute any known owner account ID.
2. Run the loop from one or more hosts.
3. The endpoint accepts every request, passes all validation, and issues a full reverse index scan per request.
4. Observe rising DB CPU/IO and increasing latency on all other mirror node API endpoints. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L57-83)
```java
    @GetMapping(value = "/nfts")
    NftAllowancesResponse getNftAllowances(
            @PathVariable EntityIdParameter id,
            @RequestParam(name = ACCOUNT_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] accountIds,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(defaultValue = "true") boolean owner,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        var field = owner ? NFT_ALLOWANCE.SPENDER : NFT_ALLOWANCE.OWNER;
        var request = NftAllowanceRequest.builder()
                .accountId(id)
                .isOwner(owner)
                .limit(limit)
                .order(order)
                .ownerOrSpenderIds(new Bound(accountIds, true, ACCOUNT_ID, field))
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, NFT_ALLOWANCE.TOKEN_ID))
                .build();

        var serviceResponse = service.getNftAllowances(request);
        var allowances = nftAllowanceMapper.map(serviceResponse);

        var sort = Sort.by(order, ACCOUNT_ID, TOKEN_ID);
        var pageable = PageRequest.of(0, limit, sort);
        var links = linkFactory.create(allowances, pageable, EXTRACTORS.get(owner));

        return new NftAllowancesResponse().allowances(allowances).links(links);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java (L27-47)
```java
    private static final Map<OrderSpec, List<SortField<?>>> SORT_ORDERS = Map.of(
            new OrderSpec(true, Direction.ASC), List.of(NFT_ALLOWANCE.SPENDER.asc(), NFT_ALLOWANCE.TOKEN_ID.asc()),
            new OrderSpec(true, Direction.DESC), List.of(NFT_ALLOWANCE.SPENDER.desc(), NFT_ALLOWANCE.TOKEN_ID.desc()),
            new OrderSpec(false, Direction.ASC), List.of(NFT_ALLOWANCE.OWNER.asc(), NFT_ALLOWANCE.TOKEN_ID.asc()),
            new OrderSpec(false, Direction.DESC), List.of(NFT_ALLOWANCE.OWNER.desc(), NFT_ALLOWANCE.TOKEN_ID.desc()));

    private final DSLContext dslContext;

    @NotNull
    @Override
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L33-53)
```java
    private void checkOwnerSpenderParamValidity(Bound ownerOrSpenderParams, Bound tokenParams) {
        if (ownerOrSpenderParams.isEmpty() && !tokenParams.isEmpty()) {
            throw new IllegalArgumentException("token.id parameter must have account.id present");
        }

        verifyRangeId(ownerOrSpenderParams);
        verifyRangeId(tokenParams);

        if (!ownerOrSpenderParams.hasLowerAndUpper()
                && tokenParams.getAdjustedLowerRangeValue() > tokenParams.adjustUpperBound()) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(Constants.TOKEN_ID));
        }

        if (tokenParams.getCardinality(RangeOperator.LT, RangeOperator.LTE) > 0
                && ownerOrSpenderParams.getCardinality(RangeOperator.EQ, RangeOperator.LTE) == 0) {
            throw new IllegalArgumentException("Requires the presence of an lte or eq account.id parameter");
        }
        if (tokenParams.getCardinality(RangeOperator.GT, RangeOperator.GTE) > 0
                && ownerOrSpenderParams.getCardinality(RangeOperator.EQ, RangeOperator.GTE) == 0) {
            throw new IllegalArgumentException("Requires the presence of an gte or eq account.id parameter");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L34-36)
```java
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```
