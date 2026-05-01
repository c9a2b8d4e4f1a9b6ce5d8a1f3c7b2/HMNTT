### Title
Unauthenticated Alias-Based DB Query Exhaustion in NftAllowanceService with No Rate Limiting or Negative Caching

### Summary
The `GET /api/v1/accounts/{id}/allowances/nfts` endpoint in the `rest-java` service accepts alias-based account IDs (e.g., Base32-encoded public key aliases) as path parameters. When the alias does not exist in the entity table, `EntityServiceImpl.lookup()` unconditionally issues a live DB query via `entityRepository.findByAlias()`, finds nothing, and throws `EntityNotFoundException`. Because the `rest-java` service has no rate limiting and `EntityServiceImpl` has no negative-result cache, an unprivileged attacker can flood this endpoint with syntactically valid but non-existent aliases, saturating the HikariCP connection pool and degrading service for legitimate users.

### Finding Description

**Exact code path:**

1. `AllowancesController.getNftAllowances()` receives the path variable `{id}` as an `EntityIdParameter` and passes it directly into `NftAllowanceRequest`. [1](#0-0) 

2. `NftAllowanceServiceImpl.getNftAllowances()` calls `entityService.lookup(request.getAccountId())` with no pre-check or caching. [2](#0-1) 

3. `EntityServiceImpl.lookup()` pattern-matches on `EntityIdAliasParameter` and calls `entityRepository.findByAlias(p.alias())` — a live DB query — then throws `EntityNotFoundException` on a miss. [3](#0-2) 

4. `EntityRepository.findByAlias()` executes a native SQL query against the `entity` table on every call with no caching. [4](#0-3) 

**Root cause — two missing defenses:**

- **No rate limiting in `rest-java`:** The throttle/rate-limit infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`, `ThrottleProperties`) exists only in the `web3` module. The `rest-java` module contains only `LoggingFilter` and `MetricsFilter` — neither enforces any per-IP or global request rate cap. [5](#0-4) 

- **No negative-result cache in `EntityServiceImpl`:** Unlike the importer's `EntityIdServiceImpl`, which wraps alias lookups in a `cacheLookup()` call backed by a Caffeine/Spring cache, `EntityServiceImpl` in `rest-java` performs a raw repository call on every invocation with no caching layer. [3](#0-2) 

### Impact Explanation

Each request with a non-existent alias consumes a HikariCP connection for the duration of the `findByAlias` query. With the default `statementTimeout` of 10 000 ms for `rest-java`, a sustained flood of concurrent requests can hold connections open long enough to exhaust the pool. Once the pool is exhausted, legitimate requests queue and eventually time out, causing HTTP 500 errors or connection-timeout responses for all users of the service. The impact is availability degradation (griefing) with no economic cost to the attacker.

### Likelihood Explanation

The attack requires no credentials, no on-chain funds, and no special knowledge beyond knowing the endpoint URL and the format of a valid Base32 alias (publicly documented). A single attacker with a modest HTTP client (e.g., `wrk`, `ab`, or a simple script) can generate thousands of requests per second. The alias format is validated syntactically before the DB call, so the attacker only needs to supply a correctly formatted alias that does not exist — trivially achievable by generating random Base32 strings of the correct length.

### Recommendation

1. **Add rate limiting to `rest-java`:** Port the `bucket4j`-based `ThrottleManager` pattern from the `web3` module, or add a Spring `HandlerInterceptor`/servlet filter that enforces a global and/or per-IP request rate cap on all `rest-java` endpoints.

2. **Add a negative-result cache for alias lookups:** In `EntityServiceImpl.lookup()`, cache `Optional.empty()` results for `EntityIdAliasParameter` lookups (with a short TTL, e.g., 30–60 s) so that repeated lookups for the same non-existent alias do not hit the database.

3. **Consider input validation at the controller layer:** Reject alias-based path parameters that cannot plausibly correspond to a real account (e.g., by checking a bloom filter or a known-valid-alias cache) before issuing a DB query.

### Proof of Concept

```bash
# Generate a valid-format but non-existent Base32 alias (32 bytes → 56 Base32 chars)
# e.g., 0.0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (padded)

# Flood the endpoint with concurrent requests using a non-existent alias
wrk -t 10 -c 200 -d 30s \
  "http://<mirror-node-host>/api/v1/accounts/0.0.HIQQEXWKW53RKN4W6XXC4Q232SYNZ3SZANVZZSUME5B5PRGXL663UAQA/allowances/nfts"

# Expected result:
# - Each request triggers entityRepository.findByAlias() → DB miss → EntityNotFoundException
# - HikariCP active connections climb to pool maximum
# - Legitimate requests begin timing out or receiving 500 errors
# - DB query latency alert fires (RestJavaQueryLatency Prometheus rule)
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L57-75)
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L30-38)
```java
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select id from entity where alias = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByAlias(byte[] alias);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/LoggingFilter.java (L18-38)
```java
class LoggingFilter extends OncePerRequestFilter {

    @SuppressWarnings("java:S1075")
    private static final String ACTUATOR_PATH = "/actuator/";

    private static final String LOG_FORMAT = "{} {} {} in {} ms: {} {}";
    private static final String SUCCESS = "Success";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        long start = System.currentTimeMillis();
        Exception cause = null;

        try {
            filterChain.doFilter(request, response);
        } catch (Exception t) {
            cause = t;
        } finally {
            logRequest(request, response, start, cause);
        }
    }
```
