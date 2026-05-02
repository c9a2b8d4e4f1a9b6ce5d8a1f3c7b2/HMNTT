All technical claims have been verified against the actual source code. Here is the result:

---

Audit Report

## Title
`findByBlockType()` Reference Equality Bypass Causes Silent Empty Response for Block `"0"` / `"0x0"` on Migrated Nodes

## Summary
`RecordFileServiceImpl.findByBlockType()` uses Java reference equality (`==`) to detect `BlockType.EARLIEST`. Numeric inputs `"0"` and `"0x0"` produce a new `BlockType("0", 0L)` object that is never the `EARLIEST` singleton, causing fallthrough to `findByIndex(0)`. On MAINNET and TESTNET deployments where `BlockNumberMigration` has shifted all record file indices by tens of millions, no row has `index = 0`, so the query silently returns `Optional.empty()` instead of the actual earliest block.

## Finding Description

**File:** `web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java`

```java
// line 20 — reference equality only
if (block == BlockType.EARLIEST) {
    return recordFileRepository.findEarliest();
} else if (block == BlockType.LATEST) {
    return recordFileRepository.findLatest();
} else if (block.isHash()) {
    return recordFileRepository.findByHash(block.name());
}
return recordFileRepository.findByIndex(block.number()); // line 28
``` [1](#0-0) 

`BlockType.EARLIEST` is defined as the singleton `new BlockType("earliest", 0L)`: [2](#0-1) 

When `BlockType.of("0")` is called, the decimal branch fires and returns `new BlockType("0", 0L)` — a distinct heap object with `name="0"`, not `name="earliest"`: [3](#0-2) 

When `BlockType.of("0x0")` is called, the hex-number branch fires and returns `new BlockType("0", 0L)` (captured group is `"0"`, not the full `"0x0"`): [4](#0-3) 

In both cases `block == BlockType.EARLIEST` is `false` (different reference, different `name` component), so execution falls through to `findByIndex(0)`.

The two repository methods behave differently:

- `findEarliest()` — `ORDER BY index ASC LIMIT 1` — always returns the row with the smallest index, regardless of its value: [5](#0-4) 

- `findByIndex(0)` — `WHERE r.index = 0` — only returns a row if a row with `index = 0` exists: [6](#0-5) 

`BlockNumberMigration` shifts every record file's `index` by a large positive offset on MAINNET (~34,305,852) and TESTNET (~22,384,256): [7](#0-6) 

After this migration, no row has `index = 0`. `findByIndex(0)` returns `Optional.empty()`. `findEarliest()` still returns the correct earliest block.

## Impact Explanation
Any JSON-RPC caller that passes `"0"` or `"0x0"` as the block parameter on a migrated MAINNET or TESTNET node receives `Optional.empty()` instead of the genesis/earliest block. This affects all methods that accept a block number (`eth_getBlockByNumber`, `eth_call`, `eth_getBalance`, etc.). EVM simulation paths that depend on genesis block context will fail silently, and applications using block 0 as an anchor will receive incorrect null/not-found responses.

## Likelihood Explanation
No privileges are required. Any user of the public JSON-RPC endpoint can trigger this by passing `"0x0"` (the standard Ethereum hex encoding of block 0) or `"0"`. MAINNET and TESTNET are confirmed affected deployments with hardcoded migration offsets. The condition is permanent post-migration and reproducible on every request. [8](#0-7) 

## Recommendation
Replace the reference equality checks in `findByBlockType()` with value-based equality using `.equals()`, or restructure the logic to compare `block.number()` for the numeric-zero case. The simplest fix is:

```java
public Optional<RecordFile> findByBlockType(BlockType block) {
    if (block.equals(BlockType.EARLIEST)) {
        return recordFileRepository.findEarliest();
    } else if (block.equals(BlockType.LATEST)) {
        return recordFileRepository.findLatest();
    } else if (block.isHash()) {
        return recordFileRepository.findByHash(block.name());
    }
    return recordFileRepository.findByIndex(block.number());
}
```

Since `BlockType` is a Java `record`, `.equals()` compares both `name` and `number` components. This still won't match `BlockType.of("0")` to `EARLIEST` (because `name` differs), so the correct fix is to also handle the numeric-zero case explicitly:

```java
if (block == BlockType.EARLIEST
        || (!block.isHash() && block.number() == 0L)) {
    return recordFileRepository.findEarliest();
}
```

This ensures that any block reference resolving to index 0 is routed through `findEarliest()`, which is migration-safe.

## Proof of Concept
1. Deploy mirror node against MAINNET or TESTNET (migration runs automatically).
2. Send: `{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0",false],"id":1}`
3. Observe: response is `{"result":null}` (empty) instead of the genesis block.
4. Send: `{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":2}`
5. Observe: response correctly returns the earliest block.

The divergence is caused solely by the `==` check routing `"0x0"` to `findByIndex(0)` (returns empty post-migration) while `"earliest"` routes to `findEarliest()` (returns correct result). [1](#0-0)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L29-30)
```java
    public static final BlockType EARLIEST = new BlockType("earliest", 0L);
    public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L59-65)
```java
        final var decimal = matcher.group(GROUP_DECIMAL);
        if (decimal != null) {
            try {
                return new BlockType(value, Long.parseLong(decimal, 10));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Decimal value out of range for block: " + value, e);
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L73-79)
```java
        final var hexNum = matcher.group(GROUP_HEX_NUM);
        if (hexNum != null) {
            try {
                return new BlockType(hexNum, Long.parseLong(hexNum, 16));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Hex value out of range for block: " + value, e);
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L23-25)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST, unless = "#result == null")
    @Query(value = "select * from record_file order by index asc limit 1", nativeQuery = true)
    Optional<RecordFile> findEarliest();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L27-29)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
    @Query("select r from RecordFile r where r.index = ?1")
    Optional<RecordFile> findByIndex(long index);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/BlockNumberMigration.java (L24-26)
```java
    static final Map<String, Pair<Long, Long>> BLOCK_NUMBER_MAPPING = Map.of(
            TESTNET, Pair.of(1656461617493248000L, 22384256L),
            MAINNET, Pair.of(1656461547557609267L, 34305852L));
```

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/BlockNumberMigration.java (L53-68)
```java
    protected void doMigrate() {
        var hederaNetwork = importerProperties.getNetwork();
        var consensusEndAndBlockNumber = BLOCK_NUMBER_MAPPING.get(hederaNetwork);

        if (consensusEndAndBlockNumber == null) {
            log.info("No block migration necessary for {} network", hederaNetwork);
            return;
        }

        long correctConsensusEnd = consensusEndAndBlockNumber.getKey();
        long correctBlockNumber = consensusEndAndBlockNumber.getValue();

        findBlockNumberByConsensusEnd(correctConsensusEnd)
                .filter(blockNumber -> blockNumber != correctBlockNumber)
                .ifPresent(blockNumber -> updateIndex(correctBlockNumber, blockNumber));
    }
```
