### Title
Permanent Cache Poisoning of `CACHE_MANAGER_RECORD_FILE_EARLIEST` via `Optional.empty()` Caching on Empty DB

### Summary
The `findEarliest()` method in `RecordFileRepository` uses `@Cacheable` with `unless = "#result == null"`, but the method returns `Optional<RecordFile>`. When the `record_file` table is empty (e.g., during the startup window before the importer writes the genesis record file), the query returns `Optional.empty()`, which is not `null`, so the `unless` guard evaluates to `false` and the empty `Optional` is permanently cached. Because `cacheManagerRecordFileEarliest` is configured with `maximumSize(1)` and **no TTL**, this poisoned entry persists for the entire process lifetime with no eviction path, causing all subsequent `eth_getBlockByNumber('earliest')` calls to return "block not found" until the process is restarted.

### Finding Description

**Code locations:**

- `web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java`, lines 190–197: cache configured with `maximumSize(1)` and no `expireAfterWrite`/`expireAfterAccess`.
- `web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java`, lines 23–25: `@Cacheable(... unless = "#result == null")` on a method returning `Optional<RecordFile>`.

**Root cause:**

Spring's `@Cacheable` `unless` SpEL expression `#result == null` evaluates against the actual Java return value. When the DB has no rows, Spring Data JPA returns `Optional.empty()` — a non-null object. The expression `Optional.empty() == null` is `false`, so the `unless` condition does not suppress caching. The empty `Optional` is stored in the Caffeine cache.

**Exploit flow:**

1. The web3 service starts and begins accepting JSON-RPC requests.
2. The importer has not yet written the genesis record file to the `record_file` table (startup race window).
3. An unprivileged attacker sends: `{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":1}`.
4. `RecordFileServiceImpl.findByBlockType(BlockType.EARLIEST)` → `recordFileRepository.findEarliest()` is called.
5. The DB query `select * from record_file order by index asc limit 1` returns no rows → `Optional.empty()`.
6. Spring evaluates `unless = "#result == null"` → `false` → `Optional.empty()` is written into the cache.
7. The cache now holds `Optional.empty()` with no TTL and no eviction mechanism.
8. All future calls to `findEarliest()` return the cached `Optional.empty()` without hitting the DB.

**Why existing checks fail:**

- `unless = "#result == null"` is the only guard. It is semantically incorrect for `Optional`-returning methods; the correct guard would be `unless = "#result == null || !#result.isPresent()"`.
- There is no `@CacheEvict` annotation anywhere in the codebase targeting `CACHE_MANAGER_RECORD_FILE_EARLIEST` — confirmed by grep showing zero `CacheEvict` usages for this cache.
- No TTL is set on the cache, so size-based eviction is the only mechanism, but with `maximumSize(1)` and a single fixed key, the poisoned entry is never displaced.

### Impact Explanation

Once poisoned, `eth_getBlockByNumber('earliest')` returns "block not found" for the entire process lifetime. Any downstream logic that uses the earliest block as a lower bound anchor — including `eth_getLogs` range validation, historical state queries, and block range iteration — will fail or return incorrect results. Recovery requires a full process restart. The impact is a persistent, operator-invisible DoS on the genesis block anchor, affecting all clients of the node until restart.

### Likelihood Explanation

The precondition (empty `record_file` table) exists on every fresh deployment and every process restart before the importer catches up. No authentication is required to call `eth_getBlockByNumber`. An attacker who monitors for node restarts (observable via connection resets or latency spikes) can reliably trigger this with a single unauthenticated HTTP request. The window may be seconds to minutes depending on importer lag. The attack is repeatable on every restart.

### Recommendation

1. Fix the `unless` condition in `RecordFileRepository.findEarliest()` to correctly exclude empty Optionals:
   ```java
   @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST,
              unless = "#result == null || !#result.isPresent()")
   ```
2. Add a TTL to `cacheManagerRecordFileEarliest` (e.g., `expireAfterWrite(10, TimeUnit.MINUTES)`) so that even if an empty result is cached, it self-heals without requiring a restart.
3. Consider adding a readiness check that prevents the web3 service from accepting requests until at least one record file exists in the DB.

### Proof of Concept

**Preconditions:** Fresh mirror node deployment where the web3 service is running but the importer has not yet written the genesis record file (or during any restart before importer catches up).

**Steps:**
```bash
# Step 1: Send eth_getBlockByNumber('earliest') before genesis record file exists
curl -X POST http://<mirror-node-web3>:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":1}'
# Response: {"result":null} or block-not-found error

# Step 2: Wait for importer to write genesis record file (verify via DB)
# psql: SELECT * FROM record_file ORDER BY index ASC LIMIT 1;
# (now returns a row)

# Step 3: Send the same request again
curl -X POST http://<mirror-node-web3>:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":2}'
# Response: still {"result":null} — cache is poisoned, DB is never queried again

# Step 4: Confirm cache is poisoned by checking that even after minutes, result remains null
# Only a process restart clears the cache
```