### Title
Permanent Caching of Empty Optional in `findEarliest()` Causes Persistent Denial of "earliest" Block Lookups

### Summary
The `CACHE_MANAGER_RECORD_FILE_EARLIEST` cache is configured with no TTL and `maximumSize=1`. The `@Cacheable` guard `unless = "#result == null"` fails to exclude `Optional.empty()` (which is a non-null object), so if `findEarliest()` is called before the genesis record file is ingested, the empty result is permanently cached. Every subsequent call to `findEarliest()` returns the stale empty Optional for the lifetime of the process, making all `block: "earliest"` queries permanently broken without a restart.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 190–197 — cache built with no expiry: [1](#0-0) 

`RecordFileRepository.java` line 23–25 — cache annotation with flawed guard: [2](#0-1) 

**Root cause:** Spring's `@Cacheable` `unless` SpEL expression `#result == null` evaluates to `false` when the result is `Optional.empty()`, because `Optional.empty()` is a non-null Java object. The Caffeine cache therefore stores the empty Optional as a valid cache entry. Since no TTL is configured (`Caffeine.newBuilder().maximumSize(1).recordStats()` — no `expireAfterWrite`/`expireAfterAccess`), this entry is never evicted.

**Failed assumption:** The developer assumed `unless = "#result == null"` would prevent caching of "no result" states. It does not — it only prevents caching of a literal Java `null`. An `Optional.empty()` passes the guard and is stored permanently.

**Exploit flow:**
1. The web3 service starts and begins accepting HTTP requests.
2. The importer has not yet ingested the genesis record file (the `record_file` table is empty or partially populated).
3. An unprivileged attacker sends any request that resolves `BlockType.EARLIEST`:
   - e.g., `POST /api/v1/contracts/call` with body `{"block": "earliest", ...}`
4. `RecordFileServiceImpl.findByBlockType(BlockType.EARLIEST)` calls `recordFileRepository.findEarliest()`. [3](#0-2) 
5. The DB query returns no rows; Spring Data JPA returns `Optional.empty()`.
6. `unless = "#result == null"` evaluates to `false` (empty Optional ≠ null), so the empty Optional is stored in the no-TTL cache.
7. All future calls to `findEarliest()` hit the cache and return `Optional.empty()` permanently — the DB is never queried again.

### Impact Explanation
Every API call that uses `block: "earliest"` (e.g., `eth_call`, `eth_estimateGas`, `eth_getBalance` at the earliest block) will permanently receive a "block not found" / empty response for the entire lifetime of the process. Historical range queries that use "earliest" as a lower bound will silently return incorrect results or errors. Recovery requires a full application restart. The scope is limited to the web3 JSON-RPC service; no direct fund theft is possible, but it constitutes a persistent, targeted denial-of-service against historical query functionality.

### Likelihood Explanation
The attack requires no credentials — only HTTP access to the web3 API endpoint. The vulnerable window exists on every fresh deployment, every restart, and any time the importer falls behind. In cloud/Kubernetes environments where the web3 pod starts independently of the importer, this window can be seconds to minutes. The attacker needs only a single well-timed HTTP request. The attack is repeatable on every restart and requires no special knowledge beyond knowing the API accepts `"earliest"` as a block parameter.

### Recommendation
Change the `unless` condition on `findEarliest()` to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME,
    cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST,
    unless = "#result == null || !#result.isPresent()"
)
```

This mirrors the correct pattern needed for `Optional`-returning methods. Alternatively, add a short TTL (e.g., `expireAfterWrite(30, TimeUnit.SECONDS)`) to `cacheManagerRecordFileEarliest()` as a defense-in-depth measure, so that even if an empty Optional is cached during startup, it will be re-evaluated shortly after. [1](#0-0) 

### Proof of Concept
1. Deploy the mirror-node web3 service against an empty or freshly initialized database (no record files ingested yet).
2. Before the importer ingests the genesis record file, send:
   ```
   POST /api/v1/contracts/call
   Content-Type: application/json
   {"block": "earliest", "data": "0x", "to": "0x0000000000000000000000000000000000000001"}
   ```
3. Observe the response indicates no block found (empty Optional path).
4. Wait for the importer to fully ingest the genesis record file (verify via DB: `SELECT count(*) FROM record_file` > 0).
5. Resend the identical request — it still returns "block not found" because `Optional.empty()` is permanently cached.
6. Restart the web3 service; the same request now succeeds, confirming the cache poisoning was the cause.

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
