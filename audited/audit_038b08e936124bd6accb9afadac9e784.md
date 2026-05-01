### Title
Permanent Cache Poisoning of Earliest Record File via Insufficient `unless` Guard on No-Expiry Cache

### Summary
`cacheManagerRecordFileEarliest()` creates a Caffeine cache with no TTL (`maximumSize(1)` only), and `findEarliest()` uses `unless = "#result == null"` to prevent caching empty results. Because the return type is `Optional<RecordFile>`, an empty database returns `Optional.empty()` — which is never `null` — so the `unless` guard fails to prevent caching, and the empty result is stored permanently. Any unprivileged user who sends an `eth_getBlockByNumber("earliest", ...)` request before the database is populated will poison this cache for the lifetime of the process.

### Finding Description

**Exact code locations:**

`web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java`, lines 190–197:
```java
@Bean(CACHE_MANAGER_RECORD_FILE_EARLIEST)
CacheManager cacheManagerRecordFileEarliest() {
    final var caffeine = Caffeine.newBuilder().maximumSize(1).recordStats();
    // ← NO expireAfterWrite, NO expireAfterAccess
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
    caffeineCacheManager.setCaffeine(caffeine);
    return caffeineCacheManager;
}
```

`web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java`, line 23:
```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST, unless = "#result == null")
Optional<RecordFile> findEarliest();
```

**Root cause:** Spring's `@Cacheable` `unless` SpEL expression `"#result == null"` evaluates against the actual return value. The method returns `Optional<RecordFile>`. When the database has no rows, the JPA query returns `Optional.empty()`. `Optional.empty()` is a non-null singleton object, so `#result == null` evaluates to `false`, meaning the `unless` condition does **not** suppress caching. The empty `Optional` is written into the no-expiry cache and stays there permanently.

**Contrast with `findLatest()`:** That cache uses `expireAfterWrite(500, TimeUnit.MILLISECONDS)`, so even if it caches an empty result, it expires in half a second. The earliest-file cache has no such safety valve.

**Exploit flow:**
1. Application starts; the web3 JSON-RPC endpoint becomes reachable before the importer has written any `record_file` rows (normal during initial sync or a fresh deployment).
2. Attacker sends: `POST /` with body `{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":1}`.
3. `RecordFileServiceImpl.findByBlockType(BlockType.EARLIEST)` calls `recordFileRepository.findEarliest()`.
4. DB query `select * from record_file order by index asc limit 1` returns zero rows → Spring Data returns `Optional.empty()`.
5. `unless = "#result == null"` → `Optional.empty() == null` → `false` → Spring caches `Optional.empty()` in the no-expiry Caffeine cache.
6. All subsequent calls to `findEarliest()` hit the cache and return `Optional.empty()` — even after the importer populates the table.
7. The only recovery is a process restart.

### Impact Explanation
Every downstream consumer that queries for the earliest block (e.g., `eth_getBlockByNumber("earliest", ...)`, block-range validation, historical EVM execution anchored to genesis) will permanently receive an empty result. This breaks any feature that depends on knowing the genesis/earliest block, and can cause incorrect error responses or silent data gaps exported to all mirror node consumers. Severity is **High**: the impact is persistent (process-lifetime), affects all users, and requires no privileges to trigger.

### Likelihood Explanation
The precondition — the web3 service being reachable before the first `record_file` row exists — is a normal operational state during initial deployment or after a database wipe. No authentication is required to call `eth_getBlockByNumber`. The attacker needs only network access to the JSON-RPC port and knowledge that the service just started (observable via connection refused → connection accepted transition, or simply by polling). The attack is a single HTTP request and is trivially repeatable across restarts if the attacker is fast enough.

### Recommendation
Fix the `unless` condition to also exclude empty `Optional` results:

```java
// Before (insufficient):
@Cacheable(..., unless = "#result == null")

// After (correct):
@Cacheable(..., unless = "#result == null || !#result.isPresent()")
```

This matches the pattern already used correctly in other caches in the codebase. Additionally, consider adding a short TTL (e.g., `expireAfterWrite(60, TimeUnit.SECONDS)`) to `cacheManagerRecordFileEarliest()` as a defense-in-depth measure, since the earliest record file is immutable once written but the cache should not be permanently poisonable.

### Proof of Concept
**Preconditions:** Fresh deployment; `record_file` table is empty; web3 JSON-RPC port is reachable.

**Step 1 — Poison the cache (single unauthenticated request):**
```bash
curl -s -X POST http://<web3-host>:8545/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":1}'
# Returns: {"result":null,...}  ← DB was empty, Optional.empty() now cached permanently
```

**Step 2 — Wait for the importer to populate `record_file`** (or insert a row manually):
```sql
INSERT INTO record_file (index, consensus_end, ...) VALUES (0, ..., ...);
```

**Step 3 — Verify the cache is permanently poisoned:**
```bash
curl -s -X POST http://<web3-host>:8545/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":2}'
# Still returns: {"result":null,...}  ← DB has data but cache returns empty forever
```

**Step 4 — Confirm recovery requires restart:**
Restart the web3 process; the same request now returns the correct genesis block. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L190-197)
```java
    @Bean(CACHE_MANAGER_RECORD_FILE_EARLIEST)
    CacheManager cacheManagerRecordFileEarliest() {
        final var caffeine = Caffeine.newBuilder().maximumSize(1).recordStats();
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCaffeine(caffeine);
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L23-25)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST, unless = "#result == null")
    @Query(value = "select * from record_file order by index asc limit 1", nativeQuery = true)
    Optional<RecordFile> findEarliest();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-22)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
```
