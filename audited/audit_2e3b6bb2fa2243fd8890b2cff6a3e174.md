### Title
Unauthenticated Unbounded Pagination Enumeration of NFT Allowance Table Due to Missing Rate Limiting in rest-java Module

### Summary
The `GET /api/v1/accounts/{id}/allowances/nfts` endpoint in `AllowancesController` is publicly accessible without authentication and has no per-IP or per-session rate limiting in the `rest-java` module. An unprivileged attacker can issue unlimited paginated requests with `limit=100` and crafted `account.id`/`token.id` range bounds to systematically walk the entire `nft_allowance` table, generating sustained database load that can degrade or deny service to legitimate users.

### Finding Description
**Code path:**
- Controller: `rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java`, line 61 — `@Max(MAX_LIMIT) int limit` caps requests at 100 rows but imposes no frequency constraint.
- Service: `rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java`, lines 21–31 — `getNftAllowances()` performs no rate check before calling `repository.findAll(request, id)`.
- Constants: `rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java`, line 35 — `MAX_LIMIT = 100`.

**Root cause:** The `rest-java` module contains no rate-limiting infrastructure for this endpoint. The only filters registered are `LoggingFilter` and `MetricsFilter` (confirmed via `rest-java/src/main/java/org/hiero/mirror/restjava/config/`). The `ThrottleManager`/`ThrottleConfiguration`/`ThrottleManagerImpl` rate-limiting components exist exclusively in the `web3` module and are not wired into `rest-java`. The `WebMvcConfiguration` registers only a parameter argument resolver and an `EntityIdParameter` converter — no throttle interceptor.

**Exploit flow:**
1. Attacker sends `GET /api/v1/accounts/0.0.1/allowances/nfts?limit=100&order=asc` — no credentials needed.
2. Response includes `links.next` with `account.id=gte:X&token.id=gt:Y` pagination cursor.
3. Attacker follows the cursor in a tight loop, advancing through the entire `nft_allowance` table 100 rows at a time.
4. Attacker repeats across all valid account IDs (or uses `account.id=gte:0.0.1` with no upper bound to scan all spenders/owners for a given account).
5. Multiple concurrent attackers or a single attacker with parallel connections multiply the DB query rate with no server-side rejection.

**Why checks fail:**
- `@Max(MAX_LIMIT)` only bounds a single response size; it does not limit request frequency.
- `checkOwnerSpenderParamValidity()` validates parameter semantics (operator combinations, range ordering) but performs zero rate or frequency enforcement.
- No authentication gate exists on the endpoint.

### Impact Explanation
Each paginated request triggers a multi-column range query against the `nft_allowance` table (keyed on `owner`/`spender`/`token_id`). Sustained high-frequency requests from one or more sources can saturate the database connection pool, increase query latency for all users, and ultimately cause HTTP 5xx errors for legitimate callers — a denial-of-service condition. Because the table is append-only and can grow to millions of rows on a production network, enumeration is both feasible and damaging.

### Likelihood Explanation
No special privileges, accounts, or on-chain state are required. Any HTTP client can reach the endpoint. The pagination cursor is self-describing (returned in `links.next`), so no reverse engineering is needed. A single script issuing requests in a loop is sufficient. The attack is trivially repeatable and automatable, making it realistic for any motivated attacker.

### Recommendation
1. **Add rate limiting to `rest-java`**: Introduce a `ThrottleInterceptor` (analogous to the `web3` `ThrottleManagerImpl`) registered in `WebMvcConfiguration` that enforces a per-IP requests-per-second limit for `/api/v1/accounts/*/allowances/nfts`.
2. **Apply at the infrastructure layer**: Deploy an API gateway or reverse proxy (e.g., nginx, Envoy) with per-IP rate limiting in front of the mirror node REST API as a defense-in-depth measure.
3. **Consider cursor opacity**: Replace the transparent `account.id=gte:X&token.id=gt:Y` pagination cursor with a signed/opaque token to prevent trivially crafted enumeration bounds, though this alone does not stop replay of legitimate cursors.

### Proof of Concept
```bash
# Step 1: Start enumeration with max limit
curl -s "https://<mirror-node>/api/v1/accounts/0.0.1/allowances/nfts?limit=100&order=asc" \
  | jq '.links.next'
# Returns: "/api/v1/accounts/0.0.1/allowances/nfts?limit=100&order=asc&account.id=gte:0.0.500&token.id=gt:0.0.1000"

# Step 2: Follow cursor in a tight loop (no delay, no auth)
NEXT="?limit=100&order=asc"
while [ -n "$NEXT" ]; do
  NEXT=$(curl -s "https://<mirror-node>/api/v1/accounts/0.0.1/allowances/nfts$NEXT" \
    | jq -r '.links.next // empty' | sed 's|.*/allowances/nfts||')
done

# Step 3: Parallelize across multiple account IDs to multiply DB load
for ACCT in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.$ACCT/allowances/nfts?limit=100" &
done
```
No credentials, no special setup. The server issues a database query for every request with no throttle applied. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L57-64)
```java
    @GetMapping(value = "/nfts")
    NftAllowancesResponse getNftAllowances(
            @PathVariable EntityIdParameter id,
            @RequestParam(name = ACCOUNT_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] accountIds,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(defaultValue = "true") boolean owner,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L21-31)
```java
    public Collection<NftAllowance> getNftAllowances(NftAllowanceRequest request) {

        var ownerOrSpenderId = request.getOwnerOrSpenderIds();
        var token = request.getTokenIds();

        checkOwnerSpenderParamValidity(ownerOrSpenderId, token);

        var id = entityService.lookup(request.getAccountId());

        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L34-36)
```java
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/WebMvcConfiguration.java (L17-32)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
final class WebMvcConfiguration implements WebMvcConfigurer {

    private final RequestParameterArgumentResolver requestParameterArgumentResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(requestParameterArgumentResolver);
    }

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(String.class, EntityIdParameter.class, EntityIdParameter::valueOf);
    }
}
```
