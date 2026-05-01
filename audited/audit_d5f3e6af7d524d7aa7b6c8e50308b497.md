### Title
Cache Miss Amplification DoS via Null-Result Non-Caching in `findByEvmAddressOrAliasAndDeletedIsFalse` with Global Rate Limit Bypass

### Summary
`findByEvmAddressOrAliasAndDeletedIsFalse()` uses `unless = "#result == null"`, meaning lookups for non-existent addresses are never cached. The global rate limiter (500 req/s, not per-IP) can be fully consumed by a single attacker, and the gas throttle is completely bypassed for requests with `gas <= 10,000`. This allows an unauthenticated attacker to force up to 500 uncached native SQL queries per second against the `entity` table, causing sustained database CPU load and denying service to legitimate users.

### Finding Description

**Code location:**
- Cache annotation: `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 39–49
- Rate limiter: `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 37–42
- Gas throttle bypass: `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java`, lines 42–47

**Root cause chain:**

1. **Null results never cached.** The `@Cacheable` annotation on `findByEvmAddressOrAliasAndDeletedIsFalse` specifies `unless = "#result == null"`. When the queried address does not exist in the database, the result is an empty `Optional` which Spring evaluates as `null` for the `unless` condition, so the miss is never stored. Every subsequent request for the same non-existent address re-executes the full native SQL query:
   ```sql
   SELECT * FROM entity WHERE (evm_address = ?1 OR alias = ?1) AND deleted IS NOT TRUE
   ```

2. **Gas throttle bypassed for low-gas requests.** `ThrottleProperties.scaleGas()` returns `0` for any `gas <= 10_000`. `gasLimitBucket.tryConsume(0)` in bucket4j always succeeds unconditionally, so the gas-based throttle provides zero protection for requests submitted with `gas=0` through `gas=10000`.

3. **Rate limit is global, not per-IP.** The single shared `rateLimitBucket` bean (default 500 req/s) is consumed across all clients. A single attacker can saturate the entire budget, leaving no capacity for legitimate users.

4. **Cache TTL is 1 second.** Even for addresses that do exist, `expireAfterWrite=1s` means the cache provides minimal protection under sustained load.

**Exploit flow:**
- Attacker calls `POST /api/v1/contracts/call` with `gas=0` (bypasses gas throttle) and a unique, non-existent `to` address per request.
- `ThrottleManagerImpl.throttle()` passes: `rateLimitBucket.tryConsume(1)` succeeds (up to 500/s); `gasLimitBucket.tryConsume(scaleGas(0)) = tryConsume(0)` always succeeds.
- EVM execution resolves the `to` address via `CommonEntityAccessor.get(address, Optional.empty())` → `entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(addressBytes)`.
- Cache lookup misses (address unknown); native SQL executes against the DB.
- Result is `Optional.empty()` → `unless = "#result == null"` prevents caching → next request for same address also hits DB.
- Attacker rotates addresses each request: 500 unique DB queries/second, all uncached.

### Impact Explanation
At 500 req/s of uncached native SQL queries, the PostgreSQL instance sustains continuous sequential or index scans on the `entity` table across both `evm_address` and `alias` columns. This elevates DB CPU utilization, increases query latency for all other operations, and can degrade or deny service to legitimate contract call users. Because the rate limit is global, the attacker simultaneously starves all legitimate traffic from the 500 req/s budget.

### Likelihood Explanation
No authentication or API key is required. The attack requires only an HTTP client capable of 500 req/s — trivially achievable from a single machine or small botnet. The gas bypass (`gas=0`) is a documented parameter in the public API. The attacker needs no knowledge of existing addresses; random 20-byte values suffice. The attack is fully repeatable and stateless.

### Recommendation
1. **Cache null/empty results** with a short TTL (e.g., 2–5 seconds) by removing `unless = "#result == null"` and replacing it with `unless = "#result != null && #result.isPresent()"` — or use a dedicated negative-result cache with a bounded size and short expiry.
2. **Implement per-IP rate limiting** (e.g., via a `ConcurrentHashMap<String, Bucket>` keyed on client IP) so a single source cannot consume the global budget.
3. **Fix the gas throttle bypass**: `scaleGas` returning `0` for `gas <= 10_000` means `tryConsume(0)` is a no-op. Apply a minimum token cost of `1` for any accepted request regardless of gas value.
4. Consider adding a minimum gas floor validation before throttle evaluation.

### Proof of Concept
```bash
# Send 500 req/s with unique non-existent addresses and gas=0 (bypasses gas throttle)
for i in $(seq 1 500); do
  ADDR=$(openssl rand -hex 20)
  curl -s -X POST http://<host>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0x${ADDR}\",\"gas\":0,\"data\":\"0x\"}" &
done
wait
# Repeat in a loop; each request triggers an uncached DB query.
# Monitor DB CPU: should show sustained elevation.
# Legitimate requests begin receiving 429 as the global rate bucket empties.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L19-19)
```java
    private static final String ENTITY_CACHE_CONFIG = "expireAfterWrite=1s,maximumSize=10000,recordStats";
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
