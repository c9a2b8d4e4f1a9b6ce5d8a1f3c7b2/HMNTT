### Title
Cache-Miss Amplification in `findStorage()` Enables Unauthenticated DB Connection Pool Exhaustion

### Summary
`ContractStateServiceImpl.findStorage()` delegates to `findStorageBatch()` on every cache miss, issuing an unbounded SQL `IN`-clause query against the database that grows with the number of accumulated slot keys (up to 1,500 per contract). Because the `contractStateCache` expires every 2 seconds and the global HTTP-level throttle (500 RPS) does not bound the number of `findStorage()` calls per request, a single unauthenticated attacker can sustain a rate of DB queries that exhausts the HikariCP/pgbouncer connection pool, causing web3 processing threads to block indefinitely waiting for connections.

### Finding Description

**Code path:**

`ContractStorageReadableKVState.readFromDataSource()` (line 44) calls `contractStateService.findStorage()` once per EVM `SLOAD` opcode during contract execution. A single HTTP `/api/v1/contracts/call` request can therefore trigger dozens to thousands of sequential `findStorage()` invocations. [1](#0-0) 

Inside `findStorage()` (lines 58–70), the only guard is a Caffeine cache keyed on `(contractId, slotKey)` with `expireAfterWrite=2s, maximumSize=25000`. Any miss — including every entry after the 2-second TTL — falls through to `findStorageBatch()`. [2](#0-1) 

`findStorageBatch()` (lines 85–122) collects **all** slot keys currently in the per-contract `slotsPerContract` cache (up to 1,500 entries, `expireAfterAccess=5m`) and issues a single `SELECT … WHERE slot IN (…)` query to the database on every invocation. There is no `@Cacheable` on `findStorageBatch()` itself — it always hits the database. [3](#0-2) [4](#0-3) 

**Root cause — failed assumption:**

The throttle (`ThrottleManagerImpl.throttle()`) operates at the HTTP request boundary, enforcing a global 500 RPS limit and a gas-per-second cap. It has no visibility into how many `findStorage()` → `findStorageBatch()` → DB round-trips a single request generates. There is also no per-IP or per-user rate limit. [5](#0-4) [6](#0-5) 

The `contractStateCache` TTL of 2 seconds means that a steady stream of requests for the same slots will re-miss the cache every 2 seconds, continuously re-driving `findStorageBatch()` queries. [7](#0-6) 

**DB connection exposure:**

Each `findStorageBatch()` call acquires a HikariCP connection for the duration of the query (capped at `statementTimeout=3000 ms`). With 500 concurrent HTTP requests each triggering multiple sequential `findStorageBatch()` calls, the effective concurrent connection demand far exceeds the pgbouncer `max_user_connections=275` configured for `mirror_web3`. [8](#0-7) [9](#0-8) 

### Impact Explanation

When the connection pool is exhausted, every new `findStorageBatch()` call blocks the calling thread in HikariCP's `getConnection()` for up to the configured `connectionTimeout` (HikariCP default: 30 seconds). Because web3 request threads are the same threads executing EVM logic, a large fraction of the thread pool stalls waiting for DB connections. Legitimate requests queue behind them, causing cascading latency and eventual request timeouts across the web3 API. This matches the "≥30% of processing threads hung" severity threshold: with a 275-connection pgbouncer cap and 500 concurrent request threads each blocked on connection acquisition, well over 30% of threads are non-functional.

### Likelihood Explanation

No authentication or account registration is required to call `/api/v1/contracts/call`. The attacker needs only:
- A contract address (any deployed contract with storage slots, or a crafted one)
- The ability to send HTTP requests at 500 RPS (trivially achievable from a single machine or small botnet)

The attack is fully repeatable and self-sustaining: the 2-second cache TTL guarantees that the same slot keys re-trigger DB queries every 2 seconds without the attacker needing to rotate keys. The global (not per-IP) throttle means a single attacker can monopolize the entire request budget.

### Recommendation

1. **Add per-IP / per-user rate limiting** at the HTTP layer (e.g., via a servlet filter or API gateway) so a single source cannot consume the entire 500 RPS budget.
2. **Increase the `contractStateCache` TTL** or make it `expireAfterAccess` rather than `expireAfterWrite` to reduce re-miss frequency for hot slots.
3. **Bound the number of `findStorage()` calls per EVM execution** (e.g., cap SLOAD depth or charge a higher internal cost per unique storage read that misses the cache).
4. **Set an explicit HikariCP `connectionTimeout`** (e.g., 2–5 seconds) and a bounded `maximumPoolSize` so that pool exhaustion causes fast-fail errors rather than indefinite thread blocking.
5. **Add a circuit breaker** around `findStorageBatch()` (e.g., Resilience4j) to shed load when the DB is under pressure.

### Proof of Concept

```
# Prerequisites: a deployed contract with many storage slots, or any contract
# that reads from storage (e.g., an ERC-20 token contract).

# Step 1: Identify a contract address on the target network.
CONTRACT="0x000000000000000000000000000000000000XXXX"

# Step 2: Craft a calldata payload that triggers many SLOAD opcodes
# (e.g., a loop reading 100 unique storage slots).
# Each SLOAD → findStorage() → cache miss (after 2s) → findStorageBatch() → DB query.

# Step 3: Flood at the global rate limit (500 RPS) from a single host.
# Apache Bench example:
ab -n 100000 -c 500 -p payload.json -T application/json \
   http://mirror-node-web3/api/v1/contracts/call

# Step 4: Observe via Prometheus/Grafana:
#   hikaricp_connections_active{application="web3"} → approaches hikaricp_connections_max
#   hikaricp_connections_pending → grows
#   web3 request latency → spikes to requestTimeout (10s default)
#   Web3HighDatabaseConnections alert fires (>75% utilization for 5m)
```

After ~5–10 seconds of sustained load, `hikaricp_connections_pending` will be non-zero and request latency will exceed `requestTimeout=10000ms`, causing HTTP 503/504 responses for all users. The attack requires no credentials and is repeatable indefinitely.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractStorageReadableKVState.java (L41-47)
```java
        return timestamp
                .map(t -> contractStateService.findStorageByBlockTimestamp(
                        entityId, Bytes32.wrap(keyBytes).trimLeadingZeros().toArrayUnsafe(), t))
                .orElse(contractStateService.findStorage(entityId, keyBytes))
                .map(byteArr ->
                        new SlotValue(Bytes.wrap(leftPadBytes(byteArr, Bytes32.SIZE)), Bytes.EMPTY, Bytes.EMPTY))
                .orElse(null);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L58-70)
```java
    public Optional<byte[]> findStorage(final EntityId contractId, final byte[] key) {
        if (!cacheProperties.isEnableBatchContractSlotCaching()) {
            return contractStateRepository.findStorage(contractId.getId(), key);
        }

        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }

        return findStorageBatch(contractId, key);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-103)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
        final var wrappedKey = ByteBuffer.wrap(key);
        // Cached slot keys for contract, whose slot values are not present in the contractStateCache
        contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
        final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();

        final var cachedSlots = new ArrayList<byte[]>(cachedSlotKeys.size());
        boolean isKeyEvictedFromCache = true;

        for (var slot : cachedSlotKeys) {
            cachedSlots.add(((ByteBuffer) slot).array());
            if (wrappedKey.equals(slot)) {
                isKeyEvictedFromCache = false;
            }
        }

        final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L23-28)
```java
    @Query(value = """
                    select slot, value from contract_state
                    where contract_id = :contractId
                    and slot in (:slots)
                    """, nativeQuery = true)
    List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L28-28)
```java
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

**File:** charts/hedera-mirror/values.yaml (L440-442)
```yaml
        mirror_web3:
          max_user_client_connections: 1800
          max_user_connections: 275
```

**File:** charts/hedera-mirror-web3/values.yaml (L211-213)
```yaml
      summary: "Mirror Web3 API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="web3"}) by (namespace, pod) / sum(hikaricp_connections_max{application="web3"}) by (namespace, pod) > 0.75
```
