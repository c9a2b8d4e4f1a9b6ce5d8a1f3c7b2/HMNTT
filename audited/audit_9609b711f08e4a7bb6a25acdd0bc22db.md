### Title
Uncached Historical Storage Queries Enable Global Rate-Limit Exhaustion and Sustained DB Load

### Summary
`ContractStateServiceImpl.findStorageByBlockTimestamp()` (line 73–76) passes every call directly to `contractStateRepository.findStorageByBlockTimestamp()` with no caching layer, unlike `findStorage()` which uses `@Cacheable`. The only protection is a global (not per-IP) token-bucket throttle of 500 RPS shared across all users. An unprivileged attacker can consume the entire global budget with historical-block requests, each of which triggers multiple uncached `contract_state_change` table scans, causing sustained DB load that degrades service for all users.

### Finding Description
**Exact code path:**

`POST /api/v1/contracts/call` → `ContractController.call()` → `throttleManager.throttle(request)` (global bucket, 500 RPS) → `contractExecutionService.processCall()` → EVM execution → `ContractStorageReadableKVState.readFromDataSource()` (line 41–44) → `ContractStateServiceImpl.findStorageByBlockTimestamp()` (line 73–76) → `contractStateRepository.findStorageByBlockTimestamp()` (no `@Cacheable`).

**Root cause — failed assumption:** The design assumes the global rate limit (500 RPS) is sufficient to bound DB load. It is not, because:

1. `findStorage()` has `@Cacheable` on the repository method (`ContractStateRepository.java` line 20), but `findStorageByBlockTimestamp()` has **no** `@Cacheable` annotation (line 54 of the same file). Every invocation hits the DB.
2. The throttle buckets (`rateLimitBucket`, `gasLimitBucket`) are Spring singleton `@Bean`s (`ThrottleConfiguration.java` lines 24–44) — a single global counter shared across all callers, with no per-IP partitioning.
3. Within a single request, EVM execution can issue many SLOAD opcodes (each cold SLOAD costs 2,100 gas; with `maxGasLimit = 15,000,000` up to ~7,000 SLOADs per request). Each SLOAD triggers a separate call to `findStorageByBlockTimestamp()` and a separate DB query.
4. `restore()` is only called in the `InvalidParametersException` catch block in `ContractController.call()` (lines 47–49). Successful historical calls do **not** refund gas, but with `gas=21,000` each request consumes only `Math.floorDiv(21000, 10000) = 2` tokens from the gas bucket (scaled by `GAS_SCALE_FACTOR = 10,000`), so the rate-limit bucket (500 RPS) is the binding constraint, not the gas bucket.

**DB query executed per storage slot access (no cache):**
```sql
SELECT coalesce(value_written, value_read) AS value
FROM contract_state_change
WHERE contract_id = ?1 AND slot = ?2 AND consensus_timestamp <= ?3
ORDER BY consensus_timestamp DESC LIMIT 1
```
This is a range scan on `contract_state_change` ordered by `consensus_timestamp` for every slot access.

### Impact Explanation
At 500 RPS (the global ceiling), with a contract that accesses 10 storage slots per call, the attacker drives 5,000 uncached `contract_state_change` scans per second. The pgbouncer pool for `mirror_web3` is capped at 275 server connections (`charts/hedera-mirror/values.yaml` line 441). Sustained query load at this rate saturates the connection pool and increases query latency for all users of the node, including non-historical calls. The `statementTimeout` of 3,000 ms (`docs/configuration.md` line 700) means slow queries time out with errors rather than completing, causing visible failures for legitimate users. No economic damage occurs; the impact is availability degradation (griefing).

### Likelihood Explanation
The attack requires no credentials, no on-chain assets, and no special knowledge beyond the public API spec (`openapi.yml` line 461–510). Any attacker with a script that sends `POST /api/v1/contracts/call` with a historical block number and a contract address that reads storage can execute this. The global rate limit is not per-IP, so a single machine at 500 RPS is sufficient. The attack is trivially repeatable and requires no setup beyond knowing a valid contract address with storage history.

### Recommendation
1. **Add a result cache for `findStorageByBlockTimestamp()`** keyed on `(contractId, slot, blockTimestamp)`. Historical data is immutable once a block is finalized, so a bounded Caffeine cache (e.g., `expireAfterWrite=5m, maximumSize=50000`) is safe and would eliminate repeated DB hits for the same `(contractId, slot, blockTimestamp)` triple.
2. **Add per-IP rate limiting** at the application or ingress layer so a single client cannot consume the entire global 500 RPS budget.
3. **Limit the number of DB queries per request** by tracking SLOAD count within a `ContractCallContext` and rejecting or short-circuiting requests that exceed a configurable threshold.

### Proof of Concept
**Preconditions:** A deployed contract on the network that reads at least one storage slot (any ERC-20 token contract suffices). Identify a valid historical block number `B` and the contract's EVM address `C`.

**Steps:**
```bash
# Send 500 historical-block contract calls per second from a single machine
# Each call reads a storage slot, triggering an uncached contract_state_change scan

for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"$C\",\"data\":\"0x<storage-reading-selector>\",\"block\":\"$B\",\"gas\":21000}" &
done
wait
# Repeat in a tight loop
```

**Result:** The global 500 RPS bucket is saturated by the attacker. Each request triggers `findStorageByBlockTimestamp()` with no cache hit, issuing a `contract_state_change` range scan. Legitimate users receive throttle errors (HTTP 429) or query timeout errors as the DB connection pool (`max_user_connections: 275`) is exhausted, degrading availability for all users of the node.