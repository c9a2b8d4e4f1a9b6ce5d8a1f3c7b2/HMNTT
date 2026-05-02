### Title
Cache Thrashing via Unbounded Contract ID Cycling Causes Sustained DB Query DoS in `findRuntimeBytecode()`

### Summary
The contract bytecode cache (`maximumSize=1000, expireAfterAccess=1h`) is globally shared and trivially exhausted by any unauthenticated caller who cycles `eth_call` requests across more than 1000 distinct contract IDs. Because the global rate limit (500 req/s) is not per-IP and does not prevent cache-miss amplification, an attacker can sustain a pattern where every request produces a DB query, converting the cache into a pass-through and saturating the database with `SELECT runtime_bytecode FROM contract WHERE id = ?` at the full allowed request rate.

### Finding Description

**Cache configuration** (`CacheProperties.java`, line 22):
```
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```
This spec is wired into the `CACHE_MANAGER_CONTRACT` bean (`EvmConfiguration.java`, lines 67–73) and applied to `ContractRepository.findRuntimeBytecode()` via `@Cacheable` (`ContractRepository.java`, lines 16–18).

**Call path on every `eth_call`**:
```
ContractController.call()
  → ContractExecutionService.processCall()
    → ContractBytecodeReadableKVState.readFromDataSource()   (line 39–47)
      → contractRepository.findRuntimeBytecode(entityId.getId())
```

**Cache condition** (`unless = "#result == null"`): The return type is `Optional<byte[]>`. An empty `Optional` is not `null`, so both hits (bytecode present) and misses (contract absent, returns `Optional.empty()`) are cached. This means the attacker does not need to enumerate real contract IDs — any Long value fills a cache slot.

**Eviction trigger**: Caffeine's Window TinyLFU evicts entries once `maximumSize=1000` is exceeded. An attacker who cycles through a working set of 1001+ unique IDs will continuously evict entries, ensuring every re-visit of a previously seen ID is a cache miss and triggers a DB query.

**Rate limiting** (`ThrottleProperties.java`, line 35; `ThrottleManagerImpl.java`, lines 37–42): The `rateLimitBucket` is a single global token bucket at 500 req/s with no per-IP or per-session partitioning. An attacker from a single IP can consume the entire 500 req/s budget. The gas throttle (`gasPerSecond = 7_500_000_000L`) does not constrain the number of distinct contract IDs targeted per second.

**Root cause**: The cache size (1000) is orders of magnitude smaller than the number of deployed contracts on Hedera mainnet/testnet (tens of thousands). The global rate limit is not a cache-miss rate limit — it permits 500 cache misses/second when the attacker's working set exceeds 1000 IDs.

### Impact Explanation
At 500 req/s with a working set of 1001 IDs in rotation, the attacker forces up to 500 `SELECT runtime_bytecode FROM contract WHERE id = ?` queries per second continuously. While each query is a simple primary-key lookup, the DB connection pool and I/O bandwidth are finite. Sustained at this rate, the DB becomes the bottleneck for all mirror-node services sharing it (REST API, importer, web3), degrading or denying service to legitimate users. The `db.statementTimeout = 3000ms` does not help because the queries complete quickly — it is the volume, not the duration, that causes saturation.

### Likelihood Explanation
The attack requires zero privileges: the `/api/v1/contracts/call` endpoint is public. The attacker needs only an HTTP client capable of 500 req/s (trivially achievable from a single machine or small botnet). No knowledge of real contract IDs is required — sequential Long values fill cache slots regardless of whether a contract exists. The attack is repeatable indefinitely and requires no on-chain transactions or tokens.

### Recommendation
1. **Increase cache size**: Raise `maximumSize` to at least 10,000–50,000 to match the realistic working set of deployed contracts, consistent with other caches in the same file (e.g., `tokenType` uses `maximumSize=100000`).
2. **Add per-IP rate limiting**: Partition the `rateLimitBucket` by client IP at the filter/servlet layer so a single source cannot consume the full global budget.
3. **Cap unique `to` addresses per time window**: Detect and throttle requests that cycle through a high cardinality of distinct contract addresses from a single source.
4. **Switch to `expireAfterWrite`**: Using `expireAfterWrite` instead of `expireAfterAccess` prevents the cache from being kept alive indefinitely by an attacker who continuously accesses entries, giving the cache a predictable refresh cycle.

### Proof of Concept
```python
import requests, itertools, threading

URL = "https://<mirror-node>/api/v1/contracts/call"
# Cycle through 1001 distinct contract IDs (long-zero EVM addresses)
ids = [f"0x{'0'*24}{i:016x}" for i in range(1, 1002)]

def send(addr):
    requests.post(URL, json={"to": addr, "data": "0x", "gas": 21000}, timeout=5)

# Saturate at 500 req/s cycling through >1000 unique addresses
for addr in itertools.cycle(ids):
    threading.Thread(target=send, args=(addr,), daemon=True).start()
    # throttle to ~500/s to stay within global rate limit
    import time; time.sleep(0.002)
```

**Expected result**: After the first 1000 unique IDs are cached, every subsequent request for a previously evicted ID triggers a `SELECT runtime_bytecode FROM contract WHERE id = ?` DB query. Monitoring `pg_stat_activity` on the mirror-node DB will show a sustained stream of these queries at the full request rate, with no cache hits for the cycling IDs.