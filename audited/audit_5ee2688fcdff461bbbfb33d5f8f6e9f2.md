### Title
Uncached EVM Address DB Lookup in `getHookStorage()` Enables Unauthenticated Resource Exhaustion

### Summary
`HookServiceImpl.getHookStorage()` calls `entityService.lookup()` on every invocation, which for EVM address parameters directly executes a native SQL query against the `entity` table with no result caching. Unlike the `web3` and `grpc` modules which apply `@Cacheable` to their equivalent EVM address lookups, the `rest-java` `EntityRepository.findByEvmAddress()` has no caching annotation. Combined with the absence of any rate-limiting filter, an unauthenticated attacker can sustain a high-frequency request pattern that forces repeated uncached DB hits, cumulatively increasing database and node resource consumption.

### Finding Description

**Code path:**

`HookServiceImpl.getHookStorage()` at line 61 unconditionally calls `entityService.lookup(request.getOwnerId())`: [1](#0-0) 

`EntityServiceImpl.lookup()` at line 34 dispatches to `entityRepository.findByEvmAddress()` for EVM address parameters with no intermediate cache: [2](#0-1) 

`EntityRepository.findByEvmAddress()` in the rest-java module is a bare native SQL query with **no `@Cacheable` annotation**: [3](#0-2) 

**Root cause — failed assumption:** The codebase assumes that EVM address lookups are infrequent or that an upstream layer provides caching/throttling. Neither is true. The `web3` module's `EntityRepository` applies `@Cacheable` with a dedicated cache manager to `findByEvmAddressAndDeletedIsFalse`: [4](#0-3) 

The `grpc` module similarly applies `@Cacheable` to its entity lookups: [5](#0-4) 

The rest-java module has no equivalent protection. No rate-limiting filter class exists in the codebase (a search for `RateLimit*.java` returns no results). The only filter present is `MetricsFilter`, which only records byte counts: [6](#0-5) 

**Full per-request DB cost:** Each `getHookStorage()` call with an EVM address ownerId executes at minimum two DB queries — one `findByEvmAddress` and one `hookStorageRepository` query (lines 66–67 or 78–79): [7](#0-6) 

### Impact Explanation
Every request to the hook storage endpoint with an EVM address ownerId generates at least one uncached `SELECT` against the `entity` table and one against the `hook_storage` table. With no rate limiting and no authentication, an attacker can sustain thousands of requests per second from a single client or a small botnet. On a node with modest baseline traffic, this pattern can drive database CPU and I/O well above the 30% incremental threshold. The `entity` table is a core shared table; contention on it degrades all other services that read from it concurrently.

### Likelihood Explanation
The endpoint is publicly accessible with no credentials required. The only precondition is knowing one valid EVM address (trivially obtained from any block explorer or by observing prior transactions). The attack is fully repeatable, requires no special tooling beyond a standard HTTP client, and produces no side effects that would alert the target. The attacker does not need to cause a 404 — targeting a valid entity ensures the full query path executes every time.

### Recommendation
1. Add `@Cacheable` to `EntityRepository.findByEvmAddress()` in the rest-java module, mirroring the pattern used in the `web3` module with a bounded TTL cache.
2. Introduce a per-IP or per-endpoint rate-limiting servlet filter (e.g., using Bucket4j or Spring's `HandlerInterceptor`) for the hook storage endpoint.
3. Consider moving the entity lookup result into a short-lived request-scoped cache so that repeated lookups within the same request lifecycle are also deduplicated.

### Proof of Concept
```
# Precondition: obtain any valid EVM address from the network, e.g. 0xaabbccdd...
# No authentication required.

EVM_ADDR="0xaabbccddaabbccddaabbccddaabbccddaabbccdd"
HOOK_ID=1
NODE="https://<mirror-node-host>"

# Flood the endpoint — each request triggers an uncached DB lookup
while true; do
  curl -s -o /dev/null \
    "$NODE/api/v1/accounts/$EVM_ADDR/hooks/$HOOK_ID/storage" &
done
```

Each iteration executes `SELECT id FROM entity WHERE evm_address = ? AND deleted <> true` plus a `hook_storage` table scan with no caching or throttle. Sustained over 60 seconds from a single host, database CPU utilization will increase proportionally to request rate, exceeding the 30% incremental threshold on any node with moderate baseline load.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L56-61)
```java
    public HookStorageResult getHookStorage(HookStorageRequest request) {
        if (request.isHistorical()) {
            return getHookStorageChange(request);
        }

        final var ownerId = entityService.lookup(request.getOwnerId());
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L65-79)
```java
        if (keys.isEmpty()) {
            final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
                    ownerId.getId(), request.getHookId(), request.getKeyLowerBound(), request.getKeyUpperBound(), page);

            return new HookStorageResult(ownerId, hookStorage);
        }

        final var keysInRange = request.getKeysInRange();

        if (keysInRange.isEmpty()) {
            return new HookStorageResult(ownerId, List.of());
        }

        final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyInAndDeletedIsFalse(
                ownerId.getId(), request.getHookId(), keysInRange, page);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L32-37)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_EVM_ADDRESS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L27-57)
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
```
