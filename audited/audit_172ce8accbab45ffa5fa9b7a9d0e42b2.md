### Title
Uncached Alias Lookup in `EntityServiceImpl` Enables DB Connection Exhaustion via Unauthenticated NFT Allowance Requests

### Summary
The `getNftAllowances()` method in `NftAllowanceServiceImpl` calls `entityService.lookup()` on every request, which for alias-type account IDs executes a raw database query with no caching. Unlike the `web3` and `grpc` modules — which both apply `@Cacheable` to alias lookups — the `rest-java` module's `EntityServiceImpl` and `EntityRepository` have no caching and no rate limiting. An unauthenticated attacker sending concurrent requests with a valid alias to the public `/api/v1/accounts/{id}/allowances/nfts` endpoint can exhaust the database connection pool and degrade mirror node availability.

### Finding Description

**Exact code path:**

`AllowancesController.getNftAllowances()` (line 75) → `NftAllowanceServiceImpl.getNftAllowances()` (line 28) → `EntityServiceImpl.lookup()` (line 33) → `EntityRepository.findByAlias()` (line 13–14). [1](#0-0) [2](#0-1) 

**Root cause — no caching on `findByAlias`:**

`rest-java/EntityRepository.findByAlias()` is a plain `@Query` with no `@Cacheable`:

```java
@Query(value = "select id from entity where alias = ?1 and deleted <> true", nativeQuery = true)
Optional<Long> findByAlias(byte[] alias);
``` [3](#0-2) 

This is a deliberate design gap compared to every other module. The `web3` module's `EntityRepository` applies `@Cacheable(cacheNames = CACHE_NAME_ALIAS, cacheManager = CACHE_MANAGER_ENTITY, ...)` to its alias lookup: [4](#0-3) 

The `grpc` module's `EntityRepository` applies `@Cacheable` to `findById`: [5](#0-4) 

The `importer` module documents that its `EntityIdService` "encapsulates caching and alias resolution": [6](#0-5) 

**No rate limiting in rest-java:**

The `rest-java` config package contains only `MetricsFilter`, `LoggingFilter`, and configuration beans — no throttle/rate-limit filter:



The `ThrottleConfiguration` and `ThrottleManagerImpl` exist exclusively in the `web3` module: [7](#0-6) 

**Endpoint is public and accepts aliases:**

The OpenAPI spec confirms the path parameter is `accountIdOrAliasOrEvmAddressPathParam`, and the controller maps it directly to `EntityIdParameter id` with no authentication: [8](#0-7) 

### Impact Explanation

Every concurrent request with an alias-based `{id}` consumes one database connection for the alias resolution query, plus a second for the `nft_allowance` table query. With a typical HikariCP pool of 10–20 connections, a few dozen concurrent attackers can saturate the pool entirely. Once the pool is exhausted, all mirror node REST-Java endpoints (not just NFT allowances) begin queuing or rejecting requests, degrading the mirror node's ability to serve data to downstream consumers and operators.

### Likelihood Explanation

The attack requires zero privileges — the endpoint is unauthenticated and publicly documented in the OpenAPI spec. The attacker only needs one valid alias (trivially obtained from any Hedera explorer or by querying the accounts endpoint). The attack is repeatable, stateless, and requires no special tooling beyond a standard HTTP load generator (e.g., `wrk`, `ab`, `hey`). The absence of both caching and rate limiting means the amplification is permanent until a fix is deployed.

### Recommendation

1. **Add `@Cacheable` to `rest-java/EntityRepository.findByAlias()` and `findByEvmAddress()`**, mirroring the pattern already used in the `web3` module with a Caffeine-backed cache manager.
2. **Add a request-rate-limiting filter to the rest-java module**, analogous to `ThrottleManagerImpl` in `web3`, applied at the servlet filter level before any service logic executes.
3. As a short-term mitigation, configure the HikariCP connection pool with a `connectionTimeout` and `maximumPoolSize` appropriate to the expected load, and return HTTP 503 quickly when the pool is exhausted rather than queuing indefinitely.

### Proof of Concept

**Preconditions:**
- Mirror node rest-java service is running and reachable.
- One valid alias for any account is known (e.g., `HIQQEXWKW53RKN4W6XXC4Q232SYNZ3SZANVZZSUME5B5PRGXL663UAQA`).

**Steps:**

```bash
# 1. Confirm the alias resolves (single request succeeds)
curl "https://<mirror-node>/api/v1/accounts/0.0.HIQQEXWKW53RKN4W6XXC4Q232SYNZ3SZANVZZSUME5B5PRGXL663UAQA/allowances/nfts"

# 2. Send sustained concurrent requests (no auth required)
hey -n 100000 -c 50 \
  "https://<mirror-node>/api/v1/accounts/0.0.HIQQEXWKW53RKN4W6XXC4Q232SYNZ3SZANVZZSUME5B5PRGXL663UAQA/allowances/nfts"

# 3. Observe: DB connection pool exhausted, all rest-java endpoints begin
#    returning 500/503, importer and other DB-sharing services degrade.
```

**Expected result:** With 50 concurrent connections and no caching or rate limiting, each request fires `SELECT id FROM entity WHERE alias = ? AND deleted <> true` directly against the database. The connection pool saturates, and subsequent requests to any rest-java endpoint fail until load subsides.

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L39-49)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_ALIAS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    @Query(value = """
            select *
            from entity
            where (evm_address = ?1 or alias = ?1) and deleted is not true
            """, nativeQuery = true)
    Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdService.java (L11-14)
```java
/**
 * This service is used to centralize the conversion logic from protobuf-based HAPI entities to its internal EntityId
 * representation. Lookup methods encapsulate caching and alias resolution.
 */
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-32)
```java
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
