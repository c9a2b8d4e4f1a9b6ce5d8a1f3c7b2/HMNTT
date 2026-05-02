### Title
Uncached EVM Address DB Lookup in `getOutstandingAirdrops()` Enables DB Connection Pool Exhaustion via Unauthenticated Requests

### Summary
The `getOutstandingAirdrops()` endpoint in `TokenAirdropsController` accepts EVM addresses as the `{id}` path variable. For each such request, `EntityServiceImpl.lookup()` calls `entityRepository.findByEvmAddress()` which executes a direct, uncached SQL query against the database. The `rest-java` module's `EntityRepository` has no `@Cacheable` annotation on `findByEvmAddress()`, and the endpoint has no rate limiting, allowing an unauthenticated attacker to flood the DB connection pool with distinct non-existent EVM address lookups and degrade mirror node processing.

### Finding Description

**Exact code path:**

1. `TokenAirdropsController.getOutstandingAirdrops()` accepts `@PathVariable EntityIdParameter id`. Any `0x<40-hex-chars>` string is parsed by `EntityIdParameter.valueOf()` into an `EntityIdEvmAddressParameter`. [1](#0-0) 

2. `processRequest()` calls `service.getAirdrops(request)`, which delegates to `TokenAirdropServiceImpl.getAirdrops()`, which calls `entityService.lookup(request.getAccountId())`. [2](#0-1) 

3. `EntityServiceImpl.lookup()` dispatches on the parameter type. For `EntityIdEvmAddressParameter`, it calls `entityRepository.findByEvmAddress(p.evmAddress())` — a direct DB query with no caching. [3](#0-2) 

4. The `rest-java` `EntityRepository.findByEvmAddress()` is a plain Spring Data JPA native query with **no `@Cacheable` annotation**. [4](#0-3) 

**Root cause / failed assumption:** The `rest-java` module's `EntityRepository` lacks caching on `findByEvmAddress()`, unlike the `web3` module's `EntityRepository` which applies `@Cacheable(cacheNames = CACHE_NAME_EVM_ADDRESS, ...)`. [5](#0-4) 

**No rate limiting in rest-java:** The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module and is not applied to the `rest-java` REST endpoints. [6](#0-5) 

### Impact Explanation
Each request with a distinct non-existent EVM address acquires a DB connection, executes `SELECT id FROM entity WHERE evm_address = ? AND deleted <> true`, finds nothing, and throws `EntityNotFoundException`. With thousands of concurrent requests, the DB connection pool is saturated. Since the mirror node's importer, REST, and other services share the same PostgreSQL backend, connection pool exhaustion degrades all mirror node processing — consistent with the ≥30% network processing degradation threshold described in the scope.

### Likelihood Explanation
No authentication, API key, or session is required. The EVM address format (`0x` + 40 hex chars) is trivially generated programmatically. An attacker can generate millions of unique addresses (e.g., incrementing a counter) and fire them in parallel with standard HTTP tooling (`wrk`, `ab`, `curl` loops). The attack is fully repeatable and requires no special knowledge of the system beyond the public API path `/api/v1/accounts/{id}/airdrops/outstanding`.

### Recommendation
1. **Add `@Cacheable` to `rest-java`'s `EntityRepository.findByEvmAddress()`**, mirroring the pattern in the `web3` module, so repeated lookups of the same address (including non-existent ones, with a short TTL negative-cache) do not hit the DB.
2. **Apply rate limiting** to the `rest-java` REST endpoints (e.g., per-IP or global request-per-second bucket using Bucket4j, as already done in `web3`).
3. **Fail fast on EVM address format**: Consider rejecting EVM address `{id}` values that cannot be resolved without a DB round-trip by adding a lightweight in-memory bloom filter or negative cache for recently-queried non-existent addresses.

### Proof of Concept
```bash
# Generate and send 5000 requests with distinct non-existent EVM addresses
for i in $(seq 1 5000); do
  ADDR=$(printf "0x%040x" $i)
  curl -s "https://<mirror-node-host>/api/v1/accounts/${ADDR}/airdrops/outstanding" &
done
wait
```

Each request triggers `SELECT id FROM entity WHERE evm_address = ? AND deleted <> true` with a unique address, no cache hit, and a new DB connection acquisition. Under sufficient concurrency, the DB connection pool is exhausted, causing timeouts and errors across all mirror node services sharing the same PostgreSQL instance.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-21)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
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
