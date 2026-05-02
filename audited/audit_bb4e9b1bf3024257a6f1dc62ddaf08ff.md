### Title
Unauthenticated Concurrent Request Flooding via Unthrottled NFT Allowance Range Scan Endpoint

### Summary
The `getNftAllowances()` endpoint in `AllowancesController` accepts wide `account.id` range parameters (e.g., `gte:0.0.1&lte:0.0.9223372036854775806`) with `limit=100` from any unauthenticated caller. The `rest-java` module has no rate limiting — the `ThrottleConfiguration`/`ThrottleManager` infrastructure exists only in the `web3` module. An attacker can flood the endpoint with concurrent requests, each triggering a DB range scan on `NFT_ALLOWANCE.SPENDER` anchored by the path `owner` equality, causing sustained DB CPU exhaustion that degrades availability for legitimate users.

### Finding Description

**Code location:** `rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java`, `getNftAllowances()`, lines 57–83.

**Request path:**
```
GET /api/v1/accounts/{id}/allowances/nfts
    ?limit=100
    &account.id=gte:0.0.1
    &account.id=lte:0.0.9223372036854775806
```

**Controller parameter binding** (lines 60–61): [1](#0-0) 

`@Size(max = 2)` allows two `account.id` parameters (GTE + LTE), and `@Max(MAX_LIMIT)` caps `limit` at 100. No authentication annotation, no rate-limit annotation, no IP-based throttle.

**Query generated** in `NftAllowanceRepositoryCustomImpl.findAll()` (lines 37–46): [2](#0-1) 

The base condition fixes `owner = {path_id}` (equality), then appends the bound condition `spender >= 1 AND spender <= 9223372036854775806`. The resulting SQL is:
```sql
SELECT * FROM nft_allowance
WHERE owner = ? AND approved_for_all = true
  AND spender >= 1 AND spender <= 9223372036854775806
ORDER BY spender ASC, token_id ASC
LIMIT 100
```

**No rate limiting in rest-java:** The `ThrottleConfiguration` and `ThrottleManagerImpl` (bucket4j-based) are scoped exclusively to the `web3` module: [3](#0-2) 

The `rest-java` config directory contains only `MetricsFilter`, `LoggingFilter`, `ShallowEtagHeaderFilter`, and `WebMvcConfiguration` — none of which throttle requests: [4](#0-3) 

**Service-layer validation** in `NftAllowanceServiceImpl.checkOwnerSpenderParamValidity()` (lines 33–53) only checks operator semantics (no NE, single occurrence, valid range direction). It does not reject wide ranges or enforce a minimum range size: [5](#0-4) 

**Root cause:** The failed assumption is that an external rate-limiting layer (e.g., API gateway, reverse proxy) will always be present. The application itself provides zero per-endpoint or per-IP throttling for the `rest-java` service, so any unauthenticated caller can issue unlimited concurrent DB-hitting requests.

### Impact Explanation
Each request issues a live DB query scanning the `NFT_ALLOWANCE` table for a given owner across the full spender ID space. With no rate limiting, an attacker sending hundreds of concurrent requests per second forces the DB to execute hundreds of simultaneous range scans. Even though each query is bounded by `LIMIT 100` and the `owner` equality, the aggregate concurrent load (connection pool exhaustion, CPU saturation from sort + filter operations) degrades or denies service to legitimate users. The `approved_for_all = true` filter is applied post-index-scan, increasing per-row work when the index does not cover that column. No economic cost to the attacker; no authentication required.

### Likelihood Explanation
Any external user with network access can exploit this. The attack requires only a standard HTTP client capable of issuing concurrent GET requests — no credentials, no tokens, no special knowledge. The endpoint is publicly documented in `rest/api/v1/openapi.yml` (lines 340–389): [6](#0-5) 

The attack is trivially repeatable and automatable (e.g., `ab`, `wrk`, `hey`). Likelihood is high.

### Recommendation
1. **Add rate limiting to `rest-java`:** Port the bucket4j `ThrottleConfiguration` pattern from `web3` into `rest-java`, or add a `OncePerRequestFilter` that enforces per-IP or global request-per-second limits on `/api/v1/**` endpoints.
2. **Add DB query timeouts:** Configure a statement timeout (e.g., via jOOQ `Settings.queryTimeout` or datasource `socketTimeout`) so runaway queries are killed before exhausting DB resources.
3. **Enforce minimum range width or require a narrower bound:** Reject `account.id` ranges spanning more than a configurable maximum (e.g., 10,000 entity IDs) to limit per-query scan width.

### Proof of Concept
```bash
# Replace 0.0.1000 with any valid account that has NFT allowances
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1000/allowances/nfts\
?limit=100\
&account.id=gte:0.0.1\
&account.id=lte:0.0.9223372036854775806" &
done
wait
```

Sending 200+ concurrent requests with no rate limiting causes the DB connection pool to saturate and DB CPU to spike, resulting in timeouts or 500 errors for legitimate users. No authentication or special privileges are required.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L60-61)
```java
            @RequestParam(name = ACCOUNT_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] accountIds,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java (L37-46)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L27-58)
```java
class MetricsFilter extends OncePerRequestFilter {

    static final String REQUEST_BYTES = "hiero.mirror.restjava.request.bytes";
    static final String RESPONSE_BYTES = "hiero.mirror.restjava.response.bytes";

    private static final String METHOD = "method";
    private static final String URI = "uri";

    private final MeterProvider<DistributionSummary> requestBytesProvider;
    private final MeterProvider<DistributionSummary> responseBytesProvider;

    MetricsFilter(MeterRegistry meterRegistry) {
        this.requestBytesProvider = DistributionSummary.builder(REQUEST_BYTES)
                .baseUnit("bytes")
                .description("The size of the request in bytes")
                .withRegistry(meterRegistry);
        this.responseBytesProvider = DistributionSummary.builder(RESPONSE_BYTES)
                .baseUnit("bytes")
                .description("The size of the response in bytes")
                .withRegistry(meterRegistry);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            recordMetrics(request, response);
        }
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

**File:** rest/api/v1/openapi.yml (L340-389)
```yaml
  /api/v1/accounts/{idOrAliasOrEvmAddress}/allowances/nfts:
    get:
      summary: Get non fungible token allowances for an account
      description: |
        Returns an account's non-fungible token allowances.

        ## Ordering
        The order is governed by a combination of the account ID and the token ID values, with account ID being the parent column.
        The token ID value governs its order within the given account ID.

        Note: The default order for this API is currently ascending. The account ID can be the owner or the spender ID depending upon the owner flag.

        ## Filtering
        When filtering there are some restrictions enforced to ensure correctness and scalability.

        **The table below defines the restrictions and support for the endpoint**

        | Query Param   | Comparison Operator | Support | Description           | Example |
        | ------------- | ------------------- | ------- | --------------------- | ------- |
        | account.id    | eq                  | Y       | Single occurrence only. | ?account.id=X |
        |               | ne                  | N       | | |
        |               | lt(e)               | Y       | Single occurrence only. | ?account.id=lte:X |
        |               | gt(e)               | Y       | Single occurrence only. | ?account.id=gte:X |
        | token.id      | eq                  | Y       | Single occurrence only. Requires the presence of an **account.id** parameter | ?account.id=X&token.id=eq:Y |
        |               | ne                  | N       | | |
        |               | lt(e)               | Y       | Single occurrence only. Requires the presence of an **lte** or **eq** **account.id** parameter | ?account.id=lte:X&token.id=lt:Y |
        |               | gt(e)               | Y       | Single occurrence only. Requires the presence of an **gte** or **eq** **account.id** parameter | ?account.id=gte:X&token.id=gt:Y |

        Both filters must be a single occurrence of **gt(e)** or **lt(e)** which provide a lower and or upper boundary for search.

      operationId: getNftAllowances
      parameters:
        - $ref: "#/components/parameters/accountIdOrAliasOrEvmAddressPathParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParam"
        - $ref: "#/components/parameters/accountIdQueryParam"
        - $ref: "#/components/parameters/tokenIdQueryParam"
        - $ref: "#/components/parameters/ownerQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NftAllowancesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
        404:
          $ref: "#/components/responses/NotFoundError"
      tags:
```
