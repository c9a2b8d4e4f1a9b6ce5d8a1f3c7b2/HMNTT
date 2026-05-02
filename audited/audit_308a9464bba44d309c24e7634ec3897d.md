### Title
Unauthenticated EVM Address Lookup Causes Uncached DB Query Flood via `getAirdrops()`, Enabling Mirror Node DoS

### Summary
Every call to `TokenAirdropServiceImpl.getAirdrops()` with an EVM address `accountId` triggers a direct, uncached database query via `EntityServiceImpl.lookup()` → `EntityRepository.findByEvmAddress()`. The rest-java module applies no rate limiting to the airdrop endpoints, and the `EntityRepository` in rest-java carries no `@Cacheable` annotation. An unprivileged attacker can flood the endpoint with random EVM addresses, saturating the shared database connection pool and starving the mirror node importer of connections needed to record new transactions.

### Finding Description

**Exact code path:**

`TokenAirdropsController` (`/api/v1/accounts/{id}/airdrops/outstanding` and `/pending`) accepts any `EntityIdParameter` as `{id}`, including `EntityIdEvmAddressParameter` (matched by the regex `^(((\\d{1,5})\\.)?((\\d{1,5})\\.)?|0x)?([A-Fa-f0-9]{40})$`). [1](#0-0) 

The controller calls `service.getAirdrops(request)`: [2](#0-1) 

Which calls `entityService.lookup(request.getAccountId())`: [3](#0-2) 

`EntityServiceImpl.lookup()` dispatches to `entityRepository.findByEvmAddress()` for EVM address parameters: [4](#0-3) 

`EntityRepository.findByEvmAddress()` in rest-java is a plain `@Query` with **no `@Cacheable` annotation**: [5](#0-4) 

**Root cause:** The rest-java `EntityRepository` does not cache EVM address lookups, unlike the web3 module's `EntityRepository` (which uses `@Cacheable(cacheNames = CACHE_NAME_EVM_ADDRESS, ...)`) and the grpc module's `EntityRepository` (which uses `@Cacheable`). Every request with an EVM address `accountId` unconditionally hits the database. [6](#0-5) 

**Why existing checks fail:** The `ThrottleConfiguration` / `ThrottleManagerImpl` rate-limiting infrastructure exists exclusively in the `web3` module and is not wired into the rest-java `TokenAirdropsController`. No per-IP, per-endpoint, or global rate limit is applied to the airdrop endpoints. [7](#0-6) 

The pgbouncer pool is shared across all mirror node components, including the importer (`mirror_importer` user, `pool_mode: session`): [8](#0-7) 

### Impact Explanation
An attacker who exhausts the shared database connection pool prevents the mirror node importer from acquiring connections to write incoming Hedera transaction data. This makes the mirror node unable to serve current state and effectively halts its transaction-recording function. The `mirror_node` user also uses `pool_mode: session`, meaning connections are held for the full session duration, accelerating pool exhaustion. The `default_pool_size` of 900 and `max_client_conn` of 2000 are finite shared resources.

### Likelihood Explanation
No authentication is required. The endpoint is publicly accessible. The attacker needs only an HTTP client capable of sending concurrent GET requests with syntactically valid but non-existent 40-hex-character EVM addresses (e.g., `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`). Because the addresses do not exist in the database, results are always empty and would not be cached even if caching were present (Spring's `unless = "#result == null"` pattern). The attack is trivially scriptable and repeatable.

### Recommendation
1. Add `@Cacheable` to `EntityRepository.findByEvmAddress()` in the rest-java module, mirroring the web3 module's pattern, with a short TTL and a negative-result cache to prevent cache-miss storms on non-existent addresses.
2. Implement endpoint-level rate limiting in the rest-java module (e.g., using bucket4j as already done in web3) applied to the `/api/v1/accounts/{id}/airdrops/*` endpoints.
3. Consider a separate, bounded connection pool for the rest-java service so that read-API saturation cannot starve the importer's write connections.

### Proof of Concept
```bash
# Send 2000 concurrent requests with random non-existent EVM addresses
for i in $(seq 1 2000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "https://<mirror-node-host>/api/v1/accounts/0x${ADDR}/airdrops/outstanding" &
done
wait
# Observe: DB connection pool exhausted; importer begins failing to write;
# mirror node REST API returns 500/timeout errors for all subsequent requests.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdEvmAddressParameter.java (L15-16)
```java
    public static final String EVM_ADDRESS_REGEX = "^(((\\d{1,5})\\.)?((\\d{1,5})\\.)?|0x)?([A-Fa-f0-9]{40})$";
    public static final Pattern EVM_ADDRESS_PATTERN = Pattern.compile(EVM_ADDRESS_REGEX);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L108-108)
```java
        var response = service.getAirdrops(request);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-21)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L30-37)
```java
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-20)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";
```

**File:** charts/hedera-mirror/values.yaml (L427-443)
```yaml
    pgbouncer:
      pgbouncer:
        default_pool_size: "900"
        ignore_startup_parameters: extra_float_digits,options,statement_timeout
        max_client_conn: "2000"
        max_prepared_statements: "512"
        pool_mode: transaction
        server_lifetime: "1200"
      users:
        mirror_node:
          pool_mode: session
        mirror_importer:
          pool_mode: session
        mirror_web3:
          max_user_client_connections: 1800
          max_user_connections: 275
    replicasPerInstance: 1
```
