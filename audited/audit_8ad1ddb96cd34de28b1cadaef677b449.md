### Title
Unbounded DB Query Amplification via Uncached `findStorageByBlockTimestamp()` with Global-Only Rate Limiting

### Summary
`ContractStateServiceImpl.findStorageByBlockTimestamp()` performs a direct, uncached database query against the `contract_state_change` table for every invocation. Unlike `findStorage()`, which uses `@Cacheable` and batch loading, the historical path has zero caching. Combined with a global (not per-IP) rate limit of 500 RPS and a gas-refund mechanism that neutralizes the gas throttle for successful read-only calls, an unprivileged attacker can monopolize the entire request budget with unique `blockTimestamp` values, forcing a fresh indexed DB scan per request and causing linear growth in database query load.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorageByBlockTimestamp()` (lines 73–76) passes directly to the repository with no cache check:

```java
// ContractStateServiceImpl.java lines 73-76
public Optional<byte[]> findStorageByBlockTimestamp(
        final EntityId entityId, final byte[] slotKeyByteArray, final long blockTimestamp) {
    return contractStateRepository.findStorageByBlockTimestamp(entityId.getId(), slotKeyByteArray, blockTimestamp);
}
```

The repository method (lines 44–54 of `ContractStateRepository.java`) carries **no `@Cacheable` annotation** (contrast with `findStorage` at line 20–21 which has `@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_CONTRACT_STATE)`):

```java
// ContractStateRepository.java lines 44-54
@Query(value = """
        select coalesce(value_written, value_read) as value
        from contract_state_change
        where contract_id = ?1 and slot = ?2 and consensus_timestamp <= ?3
        order by consensus_timestamp desc limit 1
        """, nativeQuery = true)
Optional<byte[]> findStorageByBlockTimestamp(long id, byte[] slot, long blockTimestamp);
```

This query is invoked from `ContractStorageReadableKVState.readFromDataSource()` (lines 41–43) whenever a `ContractCallContext` timestamp is present — i.e., for every historical block call.

**Rate limiting analysis:**

`ThrottleManagerImpl.throttle()` (lines 37–48) enforces two global token buckets:
- `rateLimitBucket`: 500 RPS (default), **global, not per-IP**
- `gasLimitBucket`: 7.5B gas/sec (default)

The gas bucket is effectively neutralized for successful read-only historical calls: `restoreGasToBucket()` (lines 140–151 of `ContractCallService.java`) restores `min(gasRemaining, gasLimit * gasLimitRefundPercent / 100)`. With `gasLimitRefundPercent = 100` (default), a successful call restores `gasLimit - gasUsed` tokens. For a storage-read-only call, `gasUsed` is minimal, so nearly all gas tokens are returned to the bucket each request.

**Root cause:** The cache that exists for `findStorage()` (current-state path) was never applied to `findStorageByBlockTimestamp()` (historical path). The assumption that the global RPS throttle is sufficient protection fails because: (a) it is not per-IP, so one attacker can consume the entire budget; (b) the gas throttle self-refills on success; (c) each unique `blockTimestamp` value is a distinct cache miss by definition even if caching were added naively.

### Impact Explanation

An attacker sending 500 requests/second (the global cap) with `blockTimestamp` values cycling through `current_timestamp - 1`, `current_timestamp - 2`, ..., `current_timestamp - N` forces 500 fresh range-scan queries per second against `contract_state_change`. This table can be large (it stores every state change across all contracts). Each query performs an indexed scan with `ORDER BY consensus_timestamp DESC LIMIT 1`. At 500 QPS of such scans, database CPU and I/O increase linearly. Simultaneously, legitimate users receive HTTP 429 responses because the global rate bucket is exhausted. The combined effect — DB overload plus legitimate-user starvation — satisfies the ≥30% resource consumption increase threshold at any baseline load level where the attacker's 500 QPS represents a meaningful fraction of DB capacity.

### Likelihood Explanation

No authentication or API key is required to call `POST /api/v1/contracts/call` with a historical block parameter. The attacker needs only: (1) a valid contract address, (2) any storage-reading call data, and (3) the ability to send HTTP requests at 500 RPS — trivially achievable from a single machine or small botnet. The attack is fully repeatable, requires no on-chain privileges, and is not detectable as anomalous by the existing throttle (it stays within the configured limit). The varying `blockTimestamp` values prevent any future naive caching from helping without a more sophisticated keying strategy.

### Recommendation

1. **Add per-IP rate limiting** at the ingress/load-balancer layer or within `ThrottleManagerImpl` to prevent a single source from consuming the entire global budget.
2. **Cache historical storage reads** in `findStorageByBlockTimestamp()` using a bounded TTL cache keyed on `(contractId, slot, blockTimestamp)`. Because historical state is immutable (past blocks do not change), cache entries never need invalidation and can have long TTLs.
3. **Apply a tighter gas throttle for historical calls** by not refunding gas for historical-block requests, or by applying a separate, non-refunding historical-call bucket.
4. **Add a DB query timeout** (already partially present via `hiero.mirror.web3.db.statementTimeout = 3000ms`) and consider a connection pool limit specifically for historical queries to bound blast radius.

### Proof of Concept

```bash
# Prerequisites: running mirror-node web3 instance, known contract address with storage
CONTRACT="0x000000000000000000000000000000000000ABCD"
SLOT_READ_DATA="0x<storage_read_selector>"
BASE_TS=$(date +%s%N)  # current nanosecond timestamp

# Send 500 requests/second, each with a unique blockTimestamp
# (expressed as block numbers mapping to distinct consensus timestamps)
for i in $(seq 1 5000); do
  BLOCK_NUM=$((1000000 - i))  # unique block per request
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$CONTRACT\",\"data\":\"$SLOT_READ_DATA\",\"block\":\"$BLOCK_NUM\",\"gas\":50000}" &
  # throttle to ~500 RPS
  [ $((i % 500)) -eq 0 ] && sleep 1
done

# Observe: DB CPU/IO increases linearly; legitimate requests receive HTTP 429
# Each request triggers a fresh SELECT against contract_state_change with a unique consensus_timestamp bound
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L72-76)
```java
    @Override
    public Optional<byte[]> findStorageByBlockTimestamp(
            final EntityId entityId, final byte[] slotKeyByteArray, final long blockTimestamp) {
        return contractStateRepository.findStorageByBlockTimestamp(entityId.getId(), slotKeyByteArray, blockTimestamp);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L19-21)
```java
    @Query(value = "select value from contract_state where contract_id = ?1 and slot =?2", nativeQuery = true)
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_CONTRACT_STATE)
    Optional<byte[]> findStorage(final Long contractId, final byte[] key);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L44-54)
```java
    @Query(value = """
            select
                coalesce(value_written, value_read) as value
            from contract_state_change
            where contract_id = ?1
            and slot = ?2
            and consensus_timestamp <= ?3
            order by consensus_timestamp desc
            limit 1
            """, nativeQuery = true)
    Optional<byte[]> findStorageByBlockTimestamp(long id, byte[] slot, long blockTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-48)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L140-151)
```java
    private void restoreGasToBucket(EvmTransactionResult result, long gasLimit) {
        // If the transaction fails, gasUsed is equal to gasLimit, so restore the configured refund percent
        // of the gasLimit value back in the bucket.
        final var gasLimitToRestoreBaseline = (long) (gasLimit * throttleProperties.getGasLimitRefundPercent() / 100f);
        if (result == null || (!result.isSuccessful() && gasLimit == result.gasUsed())) {
            throttleManager.restore(gasLimitToRestoreBaseline);
        } else {
            // The transaction was successful or reverted, so restore the remaining gas back in the bucket or
            // the configured refund percent of the gasLimit value back in the bucket - whichever is lower.
            final var gasRemaining = gasLimit - result.gasUsed();
            throttleManager.restore(Math.min(gasRemaining, gasLimitToRestoreBaseline));
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L22-35)
```java
    private float gasLimitRefundPercent = 100;

    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractStorageReadableKVState.java (L41-44)
```java
        return timestamp
                .map(t -> contractStateService.findStorageByBlockTimestamp(
                        entityId, Bytes32.wrap(keyBytes).trimLeadingZeros().toArrayUnsafe(), t))
                .orElse(contractStateService.findStorage(entityId, keyBytes))
```
