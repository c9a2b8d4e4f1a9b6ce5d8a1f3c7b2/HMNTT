I have verified all the technical claims against the actual codebase. Here is my assessment:

**All core code path claims check out:**

1. `TokenAirdropsController` accepts `EntityIdParameter` (including EVM address) at both `/outstanding` and `/pending` endpoints, with no rate limiting. [1](#0-0) 

2. `TokenAirdropServiceImpl.getAirdrops()` calls `entityService.lookup(request.getAccountId())` unconditionally. [2](#0-1) 

3. `EntityServiceImpl.lookup()` dispatches directly to `entityRepository.findByEvmAddress()` for `EntityIdEvmAddressParameter` with no caching layer. [3](#0-2) 

4. The rest-java `EntityRepository.findByEvmAddress()` carries no `@Cacheable` annotation — it is a plain `@Query`. [4](#0-3) 

5. By contrast, the web3 `EntityRepository.findByEvmAddressAndDeletedIsFalse()` is annotated `@Cacheable(cacheNames = CACHE_NAME_EVM_ADDRESS, ...)`. [5](#0-4) 

6. `ThrottleConfiguration` and `ThrottleManagerImpl` are exclusively in the `web3` module and are not wired into rest-java at all. [6](#0-5) [7](#0-6) 

7. When the EVM address is not found, `EntityNotFoundException` is thrown and caught by `GenericControllerAdvice` as HTTP 404 — meaning every request with a non-existent EVM address completes a full DB round-trip before returning. [8](#0-7) 

8. The pgbouncer configuration confirms `mirror_importer` uses `pool_mode: session`, and `mirror_rest_java` has **no per-user connection limits** defined (unlike `mirror_rest` and `mirror_web3` which have `max_user_client_connections` and `max_user_connections` caps). [9](#0-8) 

---

Audit Report

## Title
Unauthenticated EVM Address Lookup Causes Uncached DB Query Flood via `getAirdrops()`, Enabling Mirror Node DoS

## Summary
Every call to `TokenAirdropServiceImpl.getAirdrops()` with an EVM address `accountId` triggers a direct, uncached database query via `EntityServiceImpl.lookup()` → `EntityRepository.findByEvmAddress()`. The rest-java module applies no rate limiting to the airdrop endpoints, and the rest-java `EntityRepository` carries no `@Cacheable` annotation. An unprivileged attacker can flood the endpoint with random EVM addresses, saturating the HikariCP and pgbouncer connection pools and starving other mirror node components — including the importer — of database connections.

## Finding Description

**Exact code path:**

`TokenAirdropsController` at `/api/v1/accounts/{id}/airdrops/outstanding` and `/pending` accepts any `EntityIdParameter` as `{id}`, including `EntityIdEvmAddressParameter`. [1](#0-0) 

The controller calls `service.getAirdrops(request)`: [10](#0-9) 

Which calls `entityService.lookup(request.getAccountId())`: [11](#0-10) 

`EntityServiceImpl.lookup()` dispatches to `entityRepository.findByEvmAddress()` for EVM address parameters: [12](#0-11) 

`EntityRepository.findByEvmAddress()` in rest-java is a plain `@Query` with **no `@Cacheable` annotation**: [4](#0-3) 

**Root cause:** The rest-java `EntityRepository` does not cache EVM address lookups, unlike the web3 module's `EntityRepository` which uses `@Cacheable(cacheNames = CACHE_NAME_EVM_ADDRESS, ...)`. Every request with an EVM address `accountId` unconditionally hits the database. [5](#0-4) 

**Why existing checks fail:** The `ThrottleConfiguration` / `ThrottleManagerImpl` rate-limiting infrastructure exists exclusively in the `web3` module and is not wired into the rest-java `TokenAirdropsController`. No per-IP, per-endpoint, or global rate limit is applied to the airdrop endpoints. [13](#0-12) 

The pgbouncer pool is shared across all mirror node components. Critically, `mirror_rest_java` has **no per-user connection limits** in the pgbouncer configuration (unlike `mirror_rest` and `mirror_web3` which have `max_user_client_connections` and `max_user_connections` caps), meaning it can consume the full pool. [9](#0-8) 

## Impact Explanation
An attacker who exhausts the shared database connection pool prevents the mirror node importer from acquiring connections to write incoming Hedera transaction data. The `mirror_importer` user uses `pool_mode: session`, meaning connections are held for the full session duration, making it especially sensitive to pool starvation. The `default_pool_size` of 900 and `max_client_conn` of 2000 are finite shared resources. Because `mirror_rest_java` has no per-user pgbouncer connection cap, it can consume the entire pool. Additionally, the `statementTimeout` for `mirror_rest_java` is 20 seconds, meaning each malicious query holds a connection for up to 20 seconds before timing out, amplifying the exhaustion effect. [14](#0-13) 

## Likelihood Explanation
No authentication is required. The endpoint is publicly accessible. The attacker needs only an HTTP client capable of sending concurrent GET requests with syntactically valid but non-existent 40-hex-character EVM addresses (e.g., `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`). Because the addresses do not exist in the database, results are always empty and would not be cached even if caching were present (Spring's `unless = "#result == null"` pattern would exclude null/empty results). The attack is trivially scriptable and repeatable with no special privileges or knowledge of the system. [15](#0-14) 

## Recommendation
1. **Add caching to `EntityServiceImpl.lookup()`** for EVM address and alias lookups, mirroring the pattern used in the web3 module's `EntityRepository` with a short TTL (e.g., 1–5 seconds) and a bounded cache size. Negative results (not-found) should also be cached with a short TTL to prevent repeated DB hits for non-existent addresses.
2. **Add per-user pgbouncer connection limits** for `mirror_rest_java` in the Helm chart values, similar to the existing caps for `mirror_rest` (`max_user_client_connections: 1000`, `max_user_connections: 250`).
3. **Implement rate limiting in rest-java** for the airdrop endpoints, either via a Spring `HandlerInterceptor` or an infrastructure-level solution (e.g., Traefik rate limiting middleware), to bound the number of requests per IP per second.
4. **Reduce `statementTimeout`** for `mirror_rest_java` from 20 seconds to a lower value (e.g., 5 seconds) to limit how long each malicious query holds a connection. [16](#0-15) 

## Proof of Concept
```bash
# Flood the outstanding airdrops endpoint with random non-existent EVM addresses
# Each request triggers an uncached DB query; no authentication required
for i in $(seq 1 10000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "https://<mirror-node>/api/v1/accounts/0x${ADDR}/airdrops/outstanding" &
done
wait
```
Each concurrent request causes `EntityServiceImpl.lookup()` to call `entityRepository.findByEvmAddress()` directly against the database. With sufficient concurrency, the HikariCP pool for rest-java is exhausted, then the pgbouncer pool is saturated, and `mirror_importer` (which uses `pool_mode: session`) is starved of connections needed to record new Hedera transactions. [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L66-86)
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

    @GetMapping(value = "/pending")
    TokenAirdropsResponse getPendingAirdrops(
            @PathVariable EntityIdParameter id,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(name = SENDER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] senderIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, senderIds, limit, order, serialNumbers, tokenIds, PENDING);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L108-108)
```java
        var response = service.getAirdrops(request);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
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

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L17-20)
```java
@CustomLog
@Named
@RequiredArgsConstructor
final class ThrottleManagerImpl implements ThrottleManager {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/GenericControllerAdvice.java (L115-118)
```java
    @ExceptionHandler
    private ResponseEntity<Object> notFound(final EntityNotFoundException e, final WebRequest request) {
        return handleExceptionInternal(e, null, null, NOT_FOUND, request);
    }
```

**File:** charts/hedera-mirror/values.yaml (L366-376)
```yaml
      users:
        mirror_node:
          pool_mode: session
        mirror_importer:
          pool_mode: session
        mirror_rest:
          max_user_client_connections: 1000
          max_user_connections: 250
        mirror_web3:
          max_user_client_connections: 1000
          max_user_connections: 250
```

**File:** charts/hedera-mirror/values.yaml (L427-442)
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
```
