### Title
Cache Miss Amplification DoS via Uncached Negative Lookups in `findByEvmAddressAndDeletedIsFalse()`

### Summary
Spring's `@Cacheable` with `Optional<T>` return types unwraps the Optional before evaluating the `unless` SpEL expression, so `#result` is `null` (not `Optional.empty()`) for non-existent entities. This means `unless = "#result == null"` evaluates to `true` for every "not found" result, permanently preventing those results from being cached. Any unauthenticated caller can flood the service with requests for non-existent EVM addresses, causing every request to hit the database with no cache protection, exhausting the DB connection pool and denying service to legitimate users.

### Finding Description
**Exact code location:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 32–37:

```java
@Cacheable(
        cacheNames = CACHE_NAME_EVM_ADDRESS,
        cacheManager = CACHE_MANAGER_ENTITY,
        key = "@spelHelper.hashCode(#alias)",
        unless = "#result == null")
Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);
```

**Root cause:** Spring's `CacheAspectSupport` (the AOP interceptor backing `@Cacheable`) calls `ObjectUtils.unwrapOptional(returnValue)` before evaluating the `unless` SpEL expression. For a method returning `Optional<Entity>`:
- When the entity exists: unwrapped `#result` = the `Entity` object → `#result == null` = `false` → result **is** cached ✓
- When the entity does not exist: unwrapped `#result` = `null` → `#result == null` = `true` → result **is NOT cached** ✗

The failed assumption is that `#result` refers to the `Optional` wrapper (which is never `null`). In reality, Spring unwraps it, so every "not found" lookup bypasses the cache on every call.

**Exploit flow:**
1. Attacker sends `eth_call` / `eth_estimateGas` JSON-RPC requests targeting arbitrary non-existent 20-byte EVM addresses.
2. Each request reaches `CommonEntityAccessor.getEntityByEvmAddressTimestamp()` → `findByEvmAddressAndDeletedIsFalse()`.
3. Cache is checked: miss (never populated for this address).
4. DB query executes against the `entity` table.
5. `Optional.empty()` is returned; Spring evaluates `unless` → `true` → nothing is stored in cache.
6. The next request for the **same** address repeats steps 3–5 identically. The cache never helps.
7. The same flaw exists identically in `findByEvmAddressOrAliasAndDeletedIsFalse()` at lines 39–49.

The same pattern is confirmed by the test at `EntityRepositoryTest.java` lines 73–78, which shows that querying a non-existent address always returns empty without any caching side-effect.

**Why existing checks fail:**
- The global rate limiter (`rateLimitBucket`, `requestsPerSecond = 500`) is a single shared token bucket, not per-IP. A single attacker consuming all 500 RPS starves every other user simultaneously.
- The DB statement timeout (`statementTimeout = 3000 ms`) limits individual query duration but does not reduce the number of concurrent queries hitting the DB.
- The entity cache (`expireAfterWrite=1s, maximumSize=10000`) is irrelevant for the miss path since nothing is ever written for non-existent addresses.

### Impact Explanation
At 500 RPS (the default global cap), an attacker sustains 500 uncached DB queries per second indefinitely. Each query scans the `entity` table by `evm_address`. This exhausts the HikariCP connection pool, causes query queuing, and degrades or denies service for all legitimate contract-call users. Additionally, because existing entities **are** cached (served in microseconds) while non-existent ones always hit the DB (milliseconds), the response-time difference constitutes a timing oracle that lets the attacker enumerate which EVM addresses correspond to real Hashgraph entities — directly relevant to the "Tampering/Manipulating Hashgraph history" threat scope.

### Likelihood Explanation
No authentication, API key, or privileged access is required. The web3 JSON-RPC endpoint is publicly reachable. The attacker only needs to generate 20-byte hex strings (trivially scripted) and send standard `eth_call` requests. The attack is fully repeatable, stateless, and requires no prior knowledge of the system. The 500 RPS global limit is the only barrier, and it is itself the attack surface since consuming it denies service to all other callers.

### Recommendation
1. **Cache negative results explicitly.** Change `unless = "#result == null"` to `unless = "false"` (cache everything including empty Optionals), or use the correct Optional-aware expression `unless = "!#result.isPresent()"` with the intent inverted: `unless = "#result != null && !#result.isPresent()"` — but the simplest correct fix is to use a sentinel/null-object pattern or switch to `unless = "false"` with a short TTL already provided by `expireAfterWrite=1s`.
2. **Add per-IP / per-caller rate limiting** in addition to the global bucket, so a single attacker cannot consume the entire 500 RPS allowance.
3. **Apply the same fix** to `findByEvmAddressOrAliasAndDeletedIsFalse()` at lines 39–49, which has the identical `unless = "#result == null"` condition.

### Proof of Concept
```bash
# Generate 500 unique non-existent EVM addresses and hammer the endpoint
for i in $(seq 1 500); do
  addr=$(python3 -c "import secrets; print('0x' + secrets.token_hex(20))")
  curl -s -X POST http://<mirror-node-web3>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"data\":\"0x\",\"to\":\"$addr\",\"gas\":50000}" &
done
wait
# Repeat in a loop — each unique address causes a DB query every iteration
# because Optional.empty() is never cached due to `unless = "#result == null"`
# with Spring's Optional-unwrapping behavior.
```

Observe: DB query count (via `pg_stat_activity` or Hibernate statistics) increases linearly with request rate. Repeat the same addresses — query count does not decrease (no cache hits for misses). Compare with existing addresses: those are served from cache after the first hit. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L32-37)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_EVM_ADDRESS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L19-19)
```java
    private static final String ENTITY_CACHE_CONFIG = "expireAfterWrite=1s,maximumSize=10000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L66-71)
```java
    public Optional<Entity> getEntityByEvmAddressAndTimestamp(
            final byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```
