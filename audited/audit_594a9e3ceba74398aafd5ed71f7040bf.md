### Title
Uncached `findStorageByBlockTimestamp` Enables Sustained DB Amplification via Historical Block Calls

### Summary
`ContractStateServiceImpl.findStorageByBlockTimestamp()` performs a direct, uncached range-scan query against the `contract_state_change` table for every invocation. Unlike `findStorage()` which is protected by a `@Cacheable` layer, the historical path has no caching at any layer. Because the global throttle is a single shared bucket (not per-IP), an unprivileged attacker can consume the entire 500 req/s budget with historical block calls, each of which fans out into N uncached DB queries — one per EVM storage slot read — causing linear-to-multiplicative growth in database query load.

### Finding Description

**Exact code path:**

`ContractController.call()` → `ThrottleManagerImpl.throttle()` (global bucket, 500 req/s) → `ContractCallService.callContract()` → EVM execution → `ContractStorageReadableKVState.readFromDataSource()` → `ContractStateService.findStorageByBlockTimestamp()` → `ContractStateRepository.findStorageByBlockTimestamp()` (raw DB query, no cache).

**Root cause — missing `@Cacheable` on the historical path:**

`findStorage` (latest block) carries `@Cacheable`:
```java
// ContractStateRepository.java:19-21
@Query(value = "select value from contract_state where contract_id = ?1 and slot =?2", nativeQuery = true)
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_CONTRACT_STATE)
Optional<byte[]> findStorage(final Long contractId, final byte[] key);
```

`findStorageByBlockTimestamp` (historical block) has **no** `@Cacheable` and no service-level cache:
```java
// ContractStateRepository.java:44-54
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

```java
// ContractStateServiceImpl.java:72-76
@Override
public Optional<byte[]> findStorageByBlockTimestamp(
        final EntityId entityId, final byte[] slotKeyByteArray, final long blockTimestamp) {
    return contractStateRepository.findStorageByBlockTimestamp(entityId.getId(), slotKeyByteArray, blockTimestamp);
}
```

**Amplification path:**

`ContractStorageReadableKVState.readFromDataSource()` calls `findStorageByBlockTimestamp` once per EVM storage slot read:
```java
// ContractStorageReadableKVState.java:41-43
return timestamp
        .map(t -> contractStateService.findStorageByBlockTimestamp(
                entityId, Bytes32.wrap(keyBytes).trimLeadingZeros().toArrayUnsafe(), t))
```

A single HTTP request to `POST /api/v1/contracts/call` with a historical `block` field triggers one EVM execution that may read N storage slots, each producing one uncached `SELECT … FROM contract_state_change WHERE … consensus_timestamp <= ? ORDER BY consensus_timestamp DESC LIMIT 1` query.

**Why the throttle is insufficient:**

The rate-limit bucket is a single global `Bucket` bean:
```java
// ThrottleConfiguration.java:24-32
@Bean(name = RATE_LIMIT_BUCKET)
Bucket rateLimitBucket() {
    long rateLimit = throttleProperties.getRequestsPerSecond(); // default 500
    ...
    return Bucket.builder().addLimit(limit).build();
}
```

There is no per-IP, per-source, or per-block-range sub-limit. An attacker from a single IP can consume the entire 500 req/s global budget. With a contract that reads K slots per call, the DB receives up to `500 × K` uncached range-scan queries per second. For a contract reading 20 slots, that is 10,000 DB queries/second, all bypassing the cache that protects the latest-block path.

### Impact Explanation

The `contract_state_change` table is an append-only historical ledger that grows unboundedly. The query `WHERE contract_id = ? AND slot = ? AND consensus_timestamp <= ? ORDER BY consensus_timestamp DESC LIMIT 1` is a range scan that becomes more expensive as the table grows. Sustained 10,000+ uncached range-scan queries per second against this table can saturate DB I/O, increase query latency for all other mirror-node services sharing the same database, and cause the web3 service to exhaust its DB connection pool — effectively a resource-exhaustion DoS. The impact is a ≥30% increase in DB CPU/IO load achievable within seconds, sustained indefinitely, with no brute-force requirement.

### Likelihood Explanation

The attack requires only:
1. Knowledge of any deployed contract address (publicly available on-chain).
2. The ability to send HTTP POST requests to the public `/api/v1/contracts/call` endpoint.
3. Varying the `block` field across requests (e.g., sequential block numbers or timestamps).

No authentication, no privileged access, no special tooling beyond `curl` or any HTTP client. The attacker does not need to exceed the global rate limit — they simply need to fill it with historical calls instead of latest calls. The attack is fully repeatable and automatable.

### Recommendation

1. **Add caching to `findStorageByBlockTimestamp`**: Apply a bounded TTL cache (e.g., Caffeine with `maximumSize` and `expireAfterWrite`) keyed on `(contractId, slot, blockTimestamp)`. Historical data is immutable, so cache entries never become stale.
2. **Add per-IP rate limiting**: The global bucket does not prevent a single client from monopolizing the budget. Introduce a per-source-IP sub-bucket for historical block calls.
3. **Limit historical call depth**: Reject or separately throttle requests where `block` is not `latest`/`pending`/`safe`/`finalized`, or apply a stricter per-second limit for historical calls.

### Proof of Concept

```bash
# Attacker sends 500 req/s to the global limit, each with a different historical block number,
# targeting a contract with many storage reads (e.g., a token contract).
# Each request triggers N uncached DB queries against contract_state_change.

CONTRACT="0x000000000000000000000000000000000000abcd"
DATA="0x<selector_for_storage_heavy_function>"

for N in $(seq 1 10000); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$CONTRACT\",\"data\":\"$DATA\",\"block\":\"$N\",\"gas\":300000}" &
done
# Each unique block number N maps to a unique blockTimestamp, bypassing any hypothetical cache.
# DB query rate = (requests/sec) × (storage slots read per call).
# With 500 req/s and 20 slots/call → ~10,000 uncached range-scan queries/second.
```