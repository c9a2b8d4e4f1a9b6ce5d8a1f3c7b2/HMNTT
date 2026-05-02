### Title
Unauthenticated Cache Flooding via `findRuntimeBytecode()` Enables Cache Thrashing DoS

### Summary
The `findRuntimeBytecode()` method in `ContractRepository` caches results in a Caffeine cache bounded at `maximumSize=1000` with no per-user or per-IP rate limiting. An unprivileged attacker can issue `eth_call` requests targeting 1001+ distinct contract IDs (including non-existent ones, since `Optional.empty()` is cached due to `unless = "#result == null"`) to continuously evict legitimate entries via LRU eviction, forcing repeated expensive database queries for high-traffic contracts and degrading service for all users.

### Finding Description
**Code location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Cache configuration** (`CacheProperties.java`, line 22):
```
expireAfterAccess=1h,maximumSize=1000,recordStats
```

**Root cause — two compounding flaws:**

1. **`unless = "#result == null"` caches `Optional.empty()`**: The method returns `Optional<byte[]>`. When a contract does not exist in the database, the result is `Optional.empty()`, which is not `null`. Therefore the `unless` guard does not suppress caching of non-existent contract lookups. An attacker can use entirely fabricated `contractId` Long values; each DB miss returns `Optional.empty()`, which is stored in the cache, consuming a slot.

2. **No per-user/per-IP rate limiting**: The throttle in `ThrottleManagerImpl.throttle()` uses a single global `rateLimitBucket` (default 500 RPS) and a single global `gasLimitBucket`. There is no per-source-IP or per-session limit. A single attacker can consume the entire global budget.

**Exploit flow:**
- The attacker sends `eth_call` POST requests to `/api/v1/contracts/call` with the `to` field set to 1001 distinct contract addresses (e.g., sequential long-zero EVM addresses like `0x00000000000000000000000000000000XXXXXXXX`).
- Each request causes `ContractBytecodeReadableKVState.readFromDataSource()` → `contractRepository.findRuntimeBytecode(entityId.getId())` to be called.
- The first 1000 unique IDs fill the cache. The 1001st triggers Caffeine LRU eviction of the least-recently-used entry.
- By cycling through 1001+ IDs continuously, the attacker keeps the cache in a fully-thrashed state: no legitimate contract bytecode remains cached for more than one eviction cycle.
- Every subsequent EVM execution for a legitimate high-traffic contract must re-query the database for its bytecode.

**Why existing checks fail:**
- The global 500 RPS rate limit (`ThrottleProperties.requestsPerSecond = 500`) does not prevent cache key diversity attacks. The attacker needs only 1001 requests to permanently thrash the cache, achievable in ~2 seconds at 500 RPS.
- The gas-per-second bucket (`gasPerSecond = 7_500_000_000`) is also global and does not isolate per-user impact.
- No IP-based rate limiting, no authentication, no validation that the target `contractId` corresponds to a real contract before the cache lookup is attempted.

### Impact Explanation
Every EVM execution that calls a contract requires its runtime bytecode via `findRuntimeBytecode()`. With the cache permanently thrashed, every such call incurs a synchronous PostgreSQL query (`select runtime_bytecode from contract where id = :contractId`). Under normal load with many concurrent users calling popular contracts, this multiplies DB query volume proportionally to traffic. The DB has a `statementTimeout` of 3000 ms; under sustained cache-miss load, connection pool exhaustion or query queuing can cause request timeouts and cascading failures across the entire web3 API. The attack degrades service quality for all users without requiring any privileged access.

### Likelihood Explanation
The attack requires only the ability to send unauthenticated HTTP POST requests to the public `/api/v1/contracts/call` endpoint. No wallet, token, or account is needed. The attacker needs to generate 1001 distinct EVM addresses (trivially done by incrementing a counter). The attack is repeatable indefinitely, cheap to sustain (minimal gas values pass the throttle), and requires no special tooling beyond a basic HTTP client. A single machine can sustain the attack within the 500 RPS global budget.

### Recommendation
1. **Fix the `unless` condition** to also suppress caching of empty Optionals: change `unless = "#result == null"` to `unless = "#result == null || !#result.isPresent()"`. This prevents non-existent contract IDs from consuming cache slots, significantly raising the cost of the attack (attacker must use real contract IDs).
2. **Add per-IP rate limiting** at the servlet filter or API gateway level, independent of the global gas/RPS buckets, so a single source cannot consume the entire global budget.
3. **Increase `maximumSize`** for the contract cache or make it configurable with a higher default, reducing the number of unique IDs needed to thrash it.
4. **Validate contract existence** before cache population, or use a separate small negative-result cache (with short TTL and low max size) for non-existent IDs to prevent them from polluting the main bytecode cache.

### Proof of Concept
```bash
# Generate 1001 distinct long-zero EVM addresses and send eth_call for each
for i in $(seq 1 1001); do
  ADDR=$(printf "0x%040x" $i)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$ADDR\",\"data\":\"0x\",\"gas\":50000,\"estimate\":false,\"block\":\"latest\"}" &
done
wait

# Now repeatedly cycle through the same 1001 addresses to keep the cache thrashed
while true; do
  for i in $(seq 1 1001); do
    ADDR=$(printf "0x%040x" $i)
    curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
      -H "Content-Type: application/json" \
      -d "{\"to\":\"$ADDR\",\"data\":\"0x\",\"gas\":50000,\"estimate\":false,\"block\":\"latest\"}" &
  done
  wait
done
# Result: legitimate contract bytecode is never cached; every real eth_call hits the DB
```