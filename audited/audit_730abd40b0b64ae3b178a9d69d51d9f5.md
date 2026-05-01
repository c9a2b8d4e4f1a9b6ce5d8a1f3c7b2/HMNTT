### Title
Cache Stampede on `findByIdAndDeletedIsFalse` Due to Missing `sync=true` on `@Cacheable`

### Summary
`EntityRepository.findByIdAndDeletedIsFalse()` uses Spring's `@Cacheable` without `sync=true`, backed by a Caffeine `CaffeineCacheManager` (basic `Cache`, not `LoadingCache`). When the 1-second entity cache TTL expires, any number of concurrent threads that arrive during the miss window all bypass the cache and execute the database query simultaneously. An unprivileged external user can deliberately trigger this condition by issuing concurrent contract calls for the same entity ID, amplifying database load proportionally to the number of concurrent requests.

### Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 20–30, `findByIdAndDeletedIsFalse(Long entityId)`.

```java
@Caching(
        cacheable = {
            @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_ENTITY, unless = "#result == null"),
            @Cacheable(
                    cacheNames = CACHE_NAME,
                    cacheManager = CACHE_MANAGER_SYSTEM_ACCOUNT,
                    condition = "...",
                    unless = "#result == null")
        })
Optional<Entity> findByIdAndDeletedIsFalse(Long entityId);
```

Neither `@Cacheable` entry sets `sync=true`.

**Cache configuration** (`CacheProperties.java`, line 19):
```
expireAfterWrite=1s,maximumSize=10000,recordStats
```
The `cacheManagerEntity()` bean (`EvmConfiguration.java`, lines 99–105) constructs a plain `CaffeineCacheManager` via `setCacheSpecification()`, which produces a basic `com.github.benmanes.caffeine.cache.Cache` — not a `LoadingCache`. Caffeine's stampede protection (single-flight loading) is only available through `LoadingCache`/`AsyncLoadingCache`, which are not used here.

**Root cause / failed assumption:** Spring's `@Cacheable` without `sync=true` performs a non-atomic check-then-act: each thread independently checks the cache, finds a miss, and proceeds to invoke the underlying repository method. There is no lock or single-flight guard. The assumption that "only one thread will execute the DB query per cache miss" is false under concurrency.

**Exploit flow:**
1. Attacker identifies any valid (or invalid) entity ID accessible via the public web3 API.
2. Attacker waits for or simply relies on the 1-second TTL expiry (which recurs every second).
3. Attacker sends N concurrent `eth_call` / contract-call requests targeting the same entity ID.
4. All N threads arrive during the miss window, all find the cache empty, and all execute `SELECT * FROM entity WHERE id = ? AND deleted IS NOT TRUE` against the database simultaneously.
5. The first thread to complete stores the result; all others discard their duplicate results — but the DB has already absorbed N queries.

**Why existing checks are insufficient:**
- The global rate limit (`requestsPerSecond=500`, `gasPerSecond=1500000000`) throttles total throughput but does not prevent a burst of concurrent requests from all landing within the same sub-second miss window.
- The `unless = "#result == null"` guard only prevents caching of null/empty results; it does not address concurrent misses for the same key.
- No `sync=true` is set on any `@Cacheable` annotation in the entire web3 module (confirmed by grep across all `.java` files).

### Impact Explanation
Database query amplification: instead of 1 DB query per cache-miss cycle, the DB receives up to N queries (bounded by concurrent threads) for the same entity ID every second. With a 1-second TTL, this window reopens continuously. Under sustained attack, this degrades DB performance for all users of the mirror node, including legitimate contract call users and other API consumers. The impact is griefing / availability degradation with no direct economic loss to network participants.

### Likelihood Explanation
Exploitation requires no credentials, no special knowledge, and no on-chain transactions — only the ability to send concurrent HTTP requests to the public web3 API endpoint. The 1-second TTL guarantees a new stampede window every second, making the attack continuously repeatable. Standard HTTP load-testing tools (e.g., `wrk`, `ab`, `hey`) are sufficient. The attacker does not need to know a valid entity ID; querying non-existent IDs is equally effective since `unless = "#result == null"` prevents empty results from being cached, meaning every such request unconditionally hits the database.

### Recommendation
1. **Add `sync=true`** to both `@Cacheable` entries on `findByIdAndDeletedIsFalse`. Spring will then use a synchronized block per cache key, ensuring only one thread executes the DB query while others wait for the cached result:
   ```java
   @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_ENTITY,
              sync = true, unless = "#result == null")
   ```
   Note: `sync=true` is incompatible with `@Caching` containing multiple `@Cacheable` entries in some Spring versions — the dual-cache pattern may need to be refactored (e.g., populate the system-account cache via a `@CachePut` in a service layer after the primary cache is populated).
2. **Cache empty/absent results** with a sentinel value to prevent unbounded DB hits for non-existent entity IDs.
3. **Consider increasing the TTL** beyond 1 second if consistency requirements allow, to reduce the frequency of stampede windows.

### Proof of Concept
```bash
# Send 100 concurrent requests for the same entity ID to the web3 API
# Replace <HOST>, <CONTRACT_ADDRESS>, and <ENTITY_ID> with real values

for i in $(seq 1 100); do
  curl -s -X POST http://<HOST>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"0x...","to":"<CONTRACT_ADDRESS>","block":"latest"}' &
done
wait

# Observe in DB slow-query logs or pg_stat_activity that the same
# "SELECT * FROM entity WHERE id = ? AND deleted IS NOT TRUE"
# query appears N times simultaneously, rather than once.
# Repeat every ~1 second to sustain the amplification.
```