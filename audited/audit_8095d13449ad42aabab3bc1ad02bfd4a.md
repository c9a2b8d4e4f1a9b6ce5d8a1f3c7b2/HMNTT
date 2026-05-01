### Title
Uncached Historical Storage Queries Enable DB Connection Pool Exhaustion via Repeated `findStorageByBlockTimestamp` Calls

### Summary
`ContractStateServiceImpl.findStorageByBlockTimestamp()` passes every call directly to the repository with no caching, unlike the current-state path (`findStorage`) which is protected by `@Cacheable`. Because the global HTTP throttle (500 RPS) operates at the request level rather than the DB-query level, a single historical `eth_call` touching many storage slots multiplies into many uncached `contract_state_change` queries, allowing an unprivileged attacker to exhaust the web3 DB connection pool and deny service to all API consumers.

### Finding Description
**Code path:**

`ContractStateServiceImpl.findStorageByBlockTimestamp()` — `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`, lines 72–76:
```java
@Override
public Optional<byte[]> findStorageByBlockTimestamp(
        final EntityId entityId, final byte[] slotKeyByteArray, final long blockTimestamp) {
    return contractStateRepository.findStorageByBlockTimestamp(
            entityId.getId(), slotKeyByteArray, blockTimestamp);
}
```
No cache check, no cache write — a direct pass-through to the repository on every invocation.

`ContractStateRepository.findStorageByBlockTimestamp()` — `web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java`, lines 44–54:
```java
@Query(value = """
        select coalesce(value_written, value_read) as value
        from contract_state_change
        where contract_id = ?1
        and slot = ?2
        and consensus_timestamp <= ?3
        order by consensus_timestamp desc
        limit 1
        """, nativeQuery = true)
Optional<byte[]> findStorageByBlockTimestamp(long id, byte[] slot, long blockTimestamp);
```
No `@Cacheable` annotation (contrast with `findStorage` at line 20–21 which carries `@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_CONTRACT_STATE)`).

**Root cause / failed assumption:** The design assumes historical queries are rare or low-volume. There is no result cache keyed on `(contractId, slot, blockTimestamp)`, so identical or near-identical queries are re-executed against the DB on every call.

**Exploit flow:**
1. Attacker identifies (or deploys) a contract with many storage slots (e.g., a mapping-heavy ERC-20 or a storage-intensive DeFi contract).
2. Attacker sends historical `eth_call` requests (`POST /api/v1/contracts/call` with a non-`latest` `block` field) at the maximum allowed rate (500 RPS, default `requestsPerSecond`).
3. Each request triggers EVM execution; `ContractStorageReadableKVState.readFromDataSource()` calls `contractStateService.findStorageByBlockTimestamp()` once per storage slot accessed during execution.
4. With N slots per call × 500 RPS, the number of DB queries per second is 500 × N — all hitting `contract_state_change` with no cache absorption.
5. The HikariCP pool for `mirror_web3` is bounded (250 connections per `charts/hedera-mirror/values.yaml` line 376); once saturated, new requests queue or fail with connection-timeout errors.

### Impact Explanation
The web3 API becomes unavailable or severely degraded for all consumers. Because the throttle is global (not per-IP), a single attacker consuming all 500 RPS prevents legitimate users from receiving any service. The `contract_state_change` table is append-only and grows with every transaction, making the range scan (`consensus_timestamp <= ?3`) progressively more expensive over time, amplifying the effect. The mirror node's importer uses a separate DB user and pool, so importer writes are not directly blocked, but DB-level resource contention (CPU, I/O, lock manager) can still degrade ingestion throughput.

### Likelihood Explanation
No authentication or IP-based rate limiting is required. Any internet-accessible deployment is reachable. The attacker needs only a publicly known contract address with multiple storage slots (trivially satisfied by any mainnet DeFi contract) and the ability to send HTTP POST requests. The attack is fully repeatable and automatable with a simple script. The default throttle of 500 RPS is generous enough to sustain the attack indefinitely.

### Recommendation
1. **Add a result cache for historical storage queries.** Key on `(contractId, slot, blockTimestamp)` with a bounded TTL (e.g., 5–10 minutes, since historical data is immutable). A Caffeine cache similar to `contractStateCache` is appropriate.
2. **Add a `@Cacheable` annotation** to `ContractStateRepository.findStorageByBlockTimestamp` or implement the cache in `ContractStateServiceImpl.findStorageByBlockTimestamp` before delegating to the repository.
3. **Introduce per-IP or per-client rate limiting** in addition to the global bucket, so a single source cannot consume the entire request budget.
4. **Limit the number of DB queries per single EVM execution** for historical calls (e.g., cap the number of distinct storage slot reads per request).

### Proof of Concept
```bash
# Target: a contract with many storage slots (e.g., a Uniswap V2 pair on mainnet)
CONTRACT="0x<address_with_many_slots>"
HISTORICAL_BLOCK="0x1"   # any non-latest block number

# Send 500 concurrent historical eth_call requests per second
for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$CONTRACT\",\"data\":\"0x<storage-reading-function-selector>\",\"block\":\"$HISTORICAL_BLOCK\",\"gas\":15000000}" &
done
wait

# Repeat in a loop; observe DB connection pool metrics via:
# hikaricp_connections_pending{application="web3"} rising to pool max
# hikaricp_connections_active{application="web3"} saturated at 250
# Subsequent legitimate requests receive HTTP 500 / connection timeout
```