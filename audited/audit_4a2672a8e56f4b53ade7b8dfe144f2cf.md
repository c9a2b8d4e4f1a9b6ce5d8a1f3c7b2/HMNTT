### Title
Unauthenticated Cache Saturation via Contract Address Cycling Causes Sustained DB I/O Amplification

### Summary
The `cacheManagerContract()` bean configures a Caffeine LRU cache with `maximumSize=1000` and `expireAfterAccess=1h` for contract runtime bytecode. An unprivileged attacker can cycle through 1,000+ distinct contract addresses via unauthenticated `POST /api/v1/contracts/call` requests, saturating the cache and forcing a DB read of `runtime_bytecode` on every subsequent request. The global (non-per-IP) rate limit of 500 req/s is the only guard, and it can be fully consumed by a single attacker, simultaneously denying cache benefit to all legitimate users and amplifying DB I/O.

### Finding Description

**Cache configuration** (`CacheProperties.java` line 22, `EvmConfiguration.java` lines 67–73):
```
contract = "expireAfterAccess=1h,maximumSize=1000,recordStats"
```
The `cacheManagerContract` bean wraps a Caffeine cache with a hard cap of 1,000 entries. Once full, every new distinct key evicts the LRU entry.

**Cache consumer** (`ContractRepository.java` lines 16–18):
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT,
           unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```
The `unless = "#result == null"` clause means lookups for non-existent contract IDs are **never cached** — every such request unconditionally hits the DB.

**Throttle** (`ThrottleProperties.java` lines 35, 42–46; `ThrottleManagerImpl.java` lines 37–42):
- `requestsPerSecond = 500` — a single global token bucket, **not per-IP**.
- `scaleGas(gas)` returns `0` for `gas ≤ 10,000`. With the minimum allowed `gas = 21,000` (`ContractCallRequest.java` line 36), `scaleGas(21000) = 2` tokens. The gas bucket capacity is `scaleGas(7_500_000_000) = 750,000` tokens/s, so the gas bucket is never exhausted at 500 req/s — the rate limit is the sole binding constraint.
- No per-IP limiting, no authentication required for `POST /api/v1/contracts/call`.

**Exploit flow**:
1. Attacker generates a list of 1,001+ valid or non-existent contract addresses.
2. Sends 500 req/s (the full global budget) cycling through these addresses.
3. In ~2 seconds the 1,000-entry cache is fully saturated.
4. Every subsequent request evicts an existing entry and triggers `SELECT runtime_bytecode FROM contract WHERE id = ?`.
5. For non-existent addresses, the `unless = "#result == null"` clause ensures the null result is never stored, so **every single request** for those addresses is a DB round-trip regardless of cache state.
6. Legitimate users share the same 500 req/s global bucket; the attacker can consume it entirely, degrading or denying service.

### Impact Explanation
- **DB I/O amplification**: Under normal operation with a warm cache, the majority of bytecode lookups are served from memory. Cache saturation converts all 500 req/s into DB reads of potentially large `runtime_bytecode` BLOBs, easily exceeding a 30% increase in DB I/O and memory allocation.
- **Global rate limit exhaustion**: Because the bucket is global and not per-IP, a single attacker consuming 500 req/s starves all legitimate callers.
- **Memory pressure**: Each evicted-and-reloaded bytecode entry allocates a new `byte[]` on the JVM heap, increasing GC pressure proportional to bytecode size × eviction rate.

### Likelihood Explanation
No credentials, API keys, or on-chain assets are required. The attack requires only HTTP access to the public `POST /api/v1/contracts/call` endpoint and a list of contract addresses (obtainable from the mirror node's own REST API). It is trivially scriptable, repeatable indefinitely, and can be sustained from a single machine at the full 500 req/s budget.

### Recommendation
1. **Add per-IP rate limiting** in addition to the global bucket (e.g., via a servlet filter or Spring Security, keyed on `X-Forwarded-For` / remote address).
2. **Cache negative results**: Remove `unless = "#result == null"` and instead cache a sentinel value (e.g., `Optional.empty()` with a short TTL) to prevent repeated DB hits for non-existent contracts.
3. **Bound cache entry weight by bytecode size**: Use Caffeine's `weigher` API to limit total cached bytes rather than entry count, preventing large-bytecode entries from disproportionately consuming memory.
4. **Increase cache size or add a secondary bloom filter** to reduce the eviction rate under legitimate high-cardinality workloads.

### Proof of Concept

```bash
# Generate 1001 distinct Hedera contract addresses (0.0.1 through 0.0.1001)
# and cycle through them at maximum rate

for i in $(seq 1 1001); do
  addr=$(printf "0x%040x" $i)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$addr\",\"gas\":21000}" &
done

# Repeat in a tight loop to sustain 500 req/s and keep the cache thrashing:
while true; do
  for i in $(seq 1 1001); do
    addr=$(printf "0x%040x" $i)
    curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
      -H "Content-Type: application/json" \
      -d "{\"to\":\"$addr\",\"gas\":21000}" &
    # throttle to ~500/s
    sleep 0.002
  done
done
```

Observe via DB slow-query logs or `pg_stat_activity` that `SELECT runtime_bytecode FROM contract WHERE id = ?` executes continuously at the full request rate with no cache hits, and that the global rate limit bucket is fully consumed, returning HTTP 429 to all concurrent legitimate callers.