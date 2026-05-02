### Title
Cache Stampede in `findRuntimeBytecode` via Non-Synchronous `@Cacheable` Allows DB Connection Pool Exhaustion

### Summary
`findRuntimeBytecode` in `ContractRepository` uses Spring's `@Cacheable` backed by a `CaffeineCacheManager` that is not configured with `setSynchronous(true)`. This means concurrent threads that all miss the cache for the same `contractId` simultaneously proceed to the database with no per-key mutex. An unprivileged attacker can exploit this by sending a burst of up to 500 concurrent requests (the global rate-limit bucket capacity) for the same uncached `contractId`, causing all 500 threads to issue the same DB query simultaneously, exhausting the connection pool and degrading the web3 service.

### Finding Description

**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Cache manager setup** (`EvmConfiguration.java`, lines 67–73):
```java
CacheManager cacheManagerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME_CONTRACT));
    caffeineCacheManager.setCacheSpecification(cacheProperties.getContract());
    return caffeineCacheManager;  // NO setSynchronous(true)
}
```

**Root cause:** `CaffeineCacheManager.setSynchronous(true)` is never called. Without it, Spring's `@Cacheable` AOP proxy performs a non-atomic check-then-act: each thread independently checks the cache, finds a miss, and calls the underlying repository method. Caffeine's native `LoadingCache` (enabled by `setSynchronous(true)`) would serialize concurrent loads for the same key; the plain `CaffeineCacheManager` does not.

**Why `unless = "#result == null"` does not help:** The return type is `Optional<byte[]>`. Spring Data JPA always returns `Optional.empty()` for a no-row result — never `null`. So `#result == null` is always `false`, meaning both hits and misses are cached after the first query completes. The stampede window is the interval between the first concurrent miss and the first DB query returning — typically 1–10 ms, but with 500 simultaneous threads that window is enough for all 500 to proceed.

**Rate limiter analysis** (`ThrottleProperties.java`, line 35; `ThrottleConfiguration.java`, lines 24–32):
```java
private long requestsPerSecond = 500;  // bucket capacity = 500
```
The bucket is a global token bucket with capacity 500. A burst of exactly 500 requests arriving simultaneously all consume one token each and all pass. The rate limiter is not per-`contractId` and does not prevent per-key stampede.

**Exploit flow:**
1. Attacker identifies any `contractId` not yet in the cache (e.g., a newly deployed contract, or any valid ID after a cache eviction at the 1-hour `expireAfterAccess` boundary).
2. Attacker sends 500 concurrent HTTP requests to `/api/v1/contracts/call` targeting that `contractId`.
3. All 500 pass the global rate-limit bucket (capacity = 500).
4. All 500 threads call `findRuntimeBytecode` simultaneously, all miss the Caffeine cache, and all issue `SELECT runtime_bytecode FROM contract WHERE id = ?` to the DB.
5. HikariCP's default pool (10 connections) is immediately exhausted; the remaining ~490 threads queue for a connection.
6. Connection-acquisition timeouts fire, requests fail with 500 errors, and the web3 service is degraded for the duration of the burst.

### Impact Explanation
DB connection pool exhaustion causes cascading request failures across the web3 service. Because the rate-limit bucket refills at 500/s, an attacker can repeat the burst every second, sustaining the degradation. Mirror node instances sharing the same DB are all affected simultaneously. This maps to the stated scope: degradation of ≥30% of mirror-node processing capacity without brute-force credential attacks, achievable by any unauthenticated caller.

### Likelihood Explanation
No authentication or special privilege is required. The attacker only needs to know (or enumerate) a valid or recently-uncached `contractId`. The burst is trivially reproducible with any HTTP load-testing tool (e.g., `ab`, `wrk`, `hey`). The 1-hour `expireAfterAccess` TTL means the cache evicts entries regularly, re-opening the stampede window every hour for every cached entry. Repeatability is high.

### Recommendation
1. **Enable synchronous Caffeine loading** — call `caffeineCacheManager.setSynchronous(true)` in `cacheManagerContract()` in `EvmConfiguration.java`. This causes Caffeine to use a `LoadingCache` that serializes concurrent loads for the same key, so only one thread queries the DB while others wait for the result.
2. **Add per-IP or per-key concurrency limiting** upstream (e.g., in the controller filter chain) to prevent a single client from consuming the entire global rate-limit bucket in one burst.
3. **Increase the HikariCP connection pool** size or set an explicit `connection-timeout` to fail fast rather than queue indefinitely under load.

### Proof of Concept
```bash
# Step 1: identify an uncached contractId (e.g., 1234)
# Step 2: send 500 concurrent requests simultaneously
seq 1 500 | xargs -P500 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000' + contractId + '","data":"0x","gas":50000}'

# Expected result:
# - All 500 requests pass the rate limiter (bucket capacity = 500)
# - All 500 threads simultaneously call findRuntimeBytecode for the same uncached contractId
# - DB connection pool (default 10) is exhausted
# - ~490 requests receive 500 errors or connection-timeout errors
# - Repeat every second to sustain degradation
```