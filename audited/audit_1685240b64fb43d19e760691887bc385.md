### Title
Unsynchronized Read-Modify-Query Race in `findStorageBatch` Enables O(N²) DB Amplification

### Summary
In `ContractStateServiceImpl.findStorageBatch()`, there is no synchronization between the `putIfAbsent` that registers a new slot key and the subsequent live-view key-set snapshot used to build the batch DB query. Concurrent requests for the same `contractId` with distinct slot keys each observe the growing shared key set and independently issue overlapping `findStorageBatch` SQL queries covering all accumulated slots, producing quadratic DB load amplification with no privilege required.

### Finding Description

**Exact code path:** `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`, `findStorageBatch()`, lines 85–122.

**Root cause:** The three operations — (1) `putIfAbsent` at line 90, (2) live-view key-set snapshot at line 91, and (3) DB query at line 103 — are not atomic. Caffeine's `putIfAbsent` is individually thread-safe, but there is no lock or `computeIfAbsent`-style guard preventing multiple threads from all inserting their keys and then all reading the full accumulated key set before any of them has completed a DB query.

```java
// line 90 – thread-safe insert, but no exclusion of concurrent readers
contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
// line 91 – LIVE view; sees keys inserted by all concurrent threads
final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();
// lines 93-101 – snapshot built from live view
for (var slot : cachedSlotKeys) { cachedSlots.add(...); }
// line 103 – DB query issued with ALL accumulated keys
final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
```

**Exploit flow:**

1. N threads each call `findStorage(contractId=X, key=Kᵢ)` concurrently.
2. All N threads miss `contractStateCache` (cold start or post-expiry).
3. All N threads enter `findStorageBatch`.
4. Each thread executes `putIfAbsent(Kᵢ)` — after all N inserts, the per-contract cache contains {K₁…Kₙ}.
5. Each thread reads the live key set and sees all N keys (or a large subset, depending on scheduling).
6. Each thread issues `findStorageBatch(contractId, [K₁…Kₙ])` — the same N-slot SQL query, N times.
7. Total DB slot lookups: up to N² instead of N.

**Why existing checks fail:**

- The `contractStateCache` check at line 63–67 only short-circuits if a value is already cached. During the cold window (first access, or after the 2-second `expireAfterWrite` expiry), all concurrent threads miss it and proceed to `findStorageBatch`.
- The rate limiter (`ThrottleManagerImpl`, default 500 req/s) limits incoming HTTP requests but does not prevent the intra-process amplification: 500 allowed requests can each trigger a 500-slot batch query, yielding 250,000 slot lookups per second.
- The `slotsPerContract` cache has `maximumSize=1500` per contract. Once a contract accumulates 1500 cached slot keys (achievable over 5 minutes of normal use), each concurrent request issues a 1500-slot batch query, giving up to 500 × 1500 = 750,000 slot lookups per second from a single rate-limited attacker.

### Impact Explanation

The `findStorageBatch` SQL query is:
```sql
SELECT slot, value FROM contract_state WHERE contract_id = :contractId AND slot IN (:slots)
```
With up to 1500 elements in the `IN` clause, each query is a non-trivial indexed scan. Issuing 500 such queries per second (all for the same contract) can saturate the shared PostgreSQL instance. Because the DB is shared across all mirror-node instances, degradation propagates to every node reading from it, consistent with the ≥30% node-impact threshold. The attack is repeatable every 2 seconds (the `contractStateCache` TTL), making sustained exhaustion straightforward.

### Likelihood Explanation

The attack requires no authentication, no special contract state, and no knowledge of valid slot values — only the ability to send concurrent HTTP POST requests to `/api/v1/contracts/call` with calldata that reads different storage slots of the same contract. This is trivially achievable with any HTTP load-testing tool. The default rate limit of 500 req/s is generous enough to sustain the amplification indefinitely.

### Recommendation

Replace the non-atomic read-snapshot-query pattern with a per-contract lock or a Caffeine `compute`/`computeIfAbsent` block that atomically captures the key set and issues the DB query within a single critical section per contract:

```java
// Pseudocode: hold a per-contract lock across putIfAbsent + snapshot + query
synchronized (contractLock(contractId)) {
    contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
    List<byte[]> snapshot = snapshotKeys(contractSlotsCache);
    return contractStateRepository.findStorageBatch(contractId.getId(), snapshot);
}
```

Alternatively, use a `ConcurrentHashMap.computeIfAbsent` pattern or a `Semaphore` keyed by `contractId` to serialize the snapshot-and-query step per contract while still allowing parallelism across different contracts. Additionally, consider reducing the `slotsPerContract` `maximumSize` and adding a per-contract request coalescing mechanism (e.g., `CompletableFuture` deduplication) to prevent redundant in-flight queries.

### Proof of Concept

**Preconditions:**
- Mirror node web3 service running with `enableBatchContractSlotCaching=true` (default).
- A deployed contract at address `0xCONTRACT` with multiple storage slots.
- `contractStateCache` is cold (first access or >2 seconds since last access).

**Steps:**

```bash
# Send 500 concurrent eth_call requests, each reading a different storage slot
# of the same contract (e.g., via SLOAD of slot 0x0001, 0x0002, ..., 0x01F4)
for i in $(seq 1 500); do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0xCONTRACT\",\"data\":\"0x$(printf '%064x' $i)\",\"gas\":50000}" &
done
wait
```

**Expected result:** The DB receives up to 500 concurrent `SELECT ... WHERE slot IN (...)` queries, each containing up to 500 slot keys, for a total of up to 250,000 slot lookups in a single second. Repeating every 2 seconds sustains the load. DB CPU and I/O spike; all mirror-node instances sharing the DB experience query latency degradation.