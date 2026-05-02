### Title
Unprivileged Historical Block Requests Bypass I/O-Aware Throttling, Enabling Database Saturation

### Summary
The `callContract()` method in `ContractCallService.java` accepts any valid block number—including genesis (block 0 / `"earliest"`)—without restricting how far back in history a caller may reach. The existing throttle is calibrated purely on EVM gas units, which does not account for the significantly higher database I/O cost of historical state queries. An unprivileged attacker can flood the service with requests targeting very old blocks, triggering expensive, uncached, multi-table CTE queries for every EVM state access, saturating database I/O and degrading performance for all concurrent users.

### Finding Description

**Code path:**

`ContractController.call()` → `ThrottleManagerImpl.throttle()` (gas + rate check) → `ContractExecutionService.processCall()` → `ContractCallService.callContract(params, ctx)` (lines 100–107) → `doProcessCall()` → `TransactionExecutionService.execute()` → per-entity historical DB reads.

**Root cause — `ContractCallService.java` lines 100–107:**
```java
protected final EvmTransactionResult callContract(CallServiceParameters params, ContractCallContext ctx) {
    ctx.setCallServiceParameters(params);
    ctx.setBlockSupplier(Suppliers.memoize(() ->
            recordFileService.findByBlockType(params.getBlock())
                    .orElseThrow(BlockNumberNotFoundException::new)));
    return doProcessCall(params, params.getGas(), false);
}
```
There is **no lower-bound check** on `params.getBlock()`. `BlockType.of("0")`, `BlockType.of("earliest")`, or any arbitrarily old block number is accepted and forwarded directly to `RecordFileServiceImpl.findByBlockType()`, which issues a plain `findByIndex()` DB lookup with no age restriction.

**Throttle is gas-only — `ThrottleManagerImpl.java` lines 37–48:**
```java
public void throttle(ContractCallRequest request) {
    if (!rateLimitBucket.tryConsume(1)) { ... }
    else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) { ... }
    ...
}
```
The throttle consumes tokens proportional to the declared `gas` field. A historical call and a current-state call with identical gas values consume **identical throttle tokens**, even though historical calls trigger far more expensive database work.

**Why historical calls are more expensive:**

For every entity the EVM touches during a historical call, the state layer issues complex queries instead of simple cached lookups:

- `AccountBalanceRepository.findHistoricalAccountBalanceUpToTimestamp()` — a three-CTE query joining `account_balance` and `crypto_transfer` tables, not cached.
- `EntityRepository.findActiveByIdAndTimestamp()` — a UNION of `entity` + `entity_history`, not cached.
- `TokenRepository.findByTokenIdAndTimestamp()` — a UNION of `token` + `token_history`, not cached.
- `ContractStateService.findStorageByBlockTimestamp()` — scans `contract_state_change`.

Current-state equivalents (`findById`, etc.) are annotated `@Cacheable` and served from memory after the first hit. Historical queries use timestamp-parameterized signatures that bypass all caches.

**Failed assumption:** The throttle design assumes that EVM gas consumption is a reliable proxy for server-side resource cost. This holds for current-state calls but breaks for historical calls, where each EVM SLOAD/BALANCE opcode triggers a multi-table, multi-CTE database query against potentially years of historical data.

### Impact Explanation
An attacker submitting requests at the permitted rate (default 500 req/s, up to 15 M gas each) targeting block 0 causes the database to execute hundreds of expensive historical CTE queries per second. These queries scan `account_balance`, `entity_history`, `token_history`, and `crypto_transfer` tables with no result caching. On a production Hedera mainnet mirror node with years of history, this saturates database I/O, increases query latency for all users (REST API, current-state `eth_call`, indexing), and can cause cascading timeouts. No economic damage occurs to any on-chain user, placing this squarely in the medium griefing category.

### Likelihood Explanation
The attack requires zero privileges: any caller of the public `/api/v1/contracts/call` endpoint can set `"block": "earliest"` or `"block": "0"` in the JSON body. No authentication, no special role, no on-chain funds. The attack is trivially scriptable, repeatable, and requires no knowledge beyond the public API documentation. The only friction is the rate limit (500 req/s), which is the exact rate needed to sustain the attack.

### Recommendation
1. **Add a configurable minimum historical block age**: Reject or separately throttle requests where the resolved block timestamp is older than a configurable threshold (e.g., 30 days).
2. **Apply a separate, lower rate limit for historical calls**: In `ThrottleManagerImpl`, detect `request.getBlock() != BlockType.LATEST` and consume additional tokens from a dedicated historical-call bucket.
3. **Cache historical query results**: Apply short-lived (TTL-based) caching to historical repository methods keyed on `(entityId, blockTimestamp)` to amortize repeated identical queries.
4. **Expose a configuration knob** (`hiero.mirror.web3.throttle.historicalGasScaleFactor`) to multiply gas cost for historical calls, allowing operators to tune the cost ratio.

### Proof of Concept
```bash
# Flood with historical calls targeting genesis block
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{
      "block": "earliest",
      "to": "0x0000000000000000000000000000000000000167",
      "gas": 15000000,
      "data": "0x70a08231000000000000000000000000<any_address>"
    }' &
done
wait
# Observe: database CPU/IO spikes; concurrent REST API calls experience elevated latency
```

Each request resolves to block 0, triggers `findHistoricalAccountBalanceUpToTimestamp` and related CTE queries against the full history of the chain, and consumes the same throttle tokens as a `"block": "latest"` call. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L100-107)
```java
    protected final EvmTransactionResult callContract(CallServiceParameters params, ContractCallContext ctx)
            throws MirrorEvmTransactionException {
        ctx.setCallServiceParameters(params);
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));

        return doProcessCall(params, params.getGas(), false);
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-29)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
            return recordFileRepository.findLatest();
        } else if (block.isHash()) {
            return recordFileRepository.findByHash(block.name());
        }

        return recordFileRepository.findByIndex(block.number());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/AccountBalanceRepository.java (L59-87)
```java
    @Query(value = """
                    with balance_timestamp as (
                        select consensus_timestamp
                        from account_balance
                        where account_id = ?3 and
                            consensus_timestamp > ?2 - 2678400000000000 and
                            consensus_timestamp <= ?2
                        order by consensus_timestamp desc
                        limit 1
                    ), balance_snapshot as (
                        select ab.balance, ab.consensus_timestamp
                        from account_balance as ab, balance_timestamp as bt
                        where account_id = ?1 and
                            ab.consensus_timestamp > bt.consensus_timestamp - 2678400000000000 and
                            ab.consensus_timestamp <= bt.consensus_timestamp
                        order by ab.consensus_timestamp desc
                        limit 1
                    ), change as (
                        select sum(amount) as amount
                        from crypto_transfer as ct
                        where ct.entity_id = ?1 and
                            ct.consensus_timestamp > coalesce((select consensus_timestamp from balance_snapshot), 0) and
                            ct.consensus_timestamp <= ?2 and
                        (ct.errata is null or ct.errata <> 'DELETE')
                    )
                    select coalesce((select balance from balance_snapshot), 0) + coalesce((select amount from change), 0)
                    """, nativeQuery = true)
    Optional<Long> findHistoricalAccountBalanceUpToTimestamp(
            long accountId, long blockTimestamp, long treasuryAccountId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-47)
```java
    @Min(1)
    private long requestsPerSecond = 500;

    // Necessary since bucket4j has a max capacity and fill rate of 1 token per nanosecond
    public long getGasPerSecond() {
        return scaleGas(gasPerSecond);
    }

    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L43-82)
```java
    public static BlockType of(final String value) {
        if (StringUtils.isEmpty(value)) {
            return LATEST;
        }

        final var blockTypeValue = value.toLowerCase(Locale.ROOT);
        final var matcher = BLOCK_PATTERN.matcher(blockTypeValue);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid block value: " + value);
        }

        final var tag = matcher.group(GROUP_TAG);
        if (tag != null) {
            return blockTypeForTag(tag);
        }

        final var decimal = matcher.group(GROUP_DECIMAL);
        if (decimal != null) {
            try {
                return new BlockType(value, Long.parseLong(decimal, 10));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Decimal value out of range for block: " + value, e);
            }
        }

        var hash = matcher.group(GROUP_HASH);
        if (hash != null) {
            return new BlockType(hash, BLOCK_HASH_SENTINEL);
        }

        final var hexNum = matcher.group(GROUP_HEX_NUM);
        if (hexNum != null) {
            try {
                return new BlockType(hexNum, Long.parseLong(hexNum, 16));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Hex value out of range for block: " + value, e);
            }
        }
        throw new IllegalArgumentException("Invalid block value: " + value);
    }
```
