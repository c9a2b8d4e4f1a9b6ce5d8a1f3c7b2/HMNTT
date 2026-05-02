All code references check out. Here is the audit report:

---

Audit Report

## Title
Reference Equality (`==`) Bypass in `findByBlockType()` Causes Block 0 Numeric Inputs to Miss Genesis Block

## Summary
`RecordFileServiceImpl.findByBlockType()` guards the `findEarliest()` path with a Java reference equality check (`block == BlockType.EARLIEST`). Any numeric representation of block 0 — `"0x00"`, `"0x0"`, `"0"` — causes `BlockType.of()` to construct a **new** `BlockType` object that is not the `EARLIEST` singleton, so the guard fails and `findByIndex(0)` is called instead. On mainnet and testnet, `BlockNumberMigration` shifts all block indices to start at ~34 M and ~22 M respectively, so no row has `index = 0` and `findByIndex(0)` returns `Optional.empty()`.

## Finding Description

**`BlockType.EARLIEST` singleton definition** — `BlockType.java` line 29:
```java
public static final BlockType EARLIEST = new BlockType("earliest", 0L);
``` [1](#0-0) 

**Hex-number branch in `BlockType.of()`** — `BlockType.java` lines 73–79: input `"0x00"` is lowercased to `"0x00"`, matches `GROUP_HEX_NUM` with `hexNum = "00"`, and returns `new BlockType("00", 0L)` — a fresh object, not the singleton: [2](#0-1) 

Decimal `"0"` takes the `GROUP_DECIMAL` branch at line 62 and returns `new BlockType("0", 0L)` — also a fresh object: [3](#0-2) 

**Reference equality guard in `findByBlockType()`** — `RecordFileServiceImpl.java` lines 20–28: the `==` check is `false` for any newly constructed object, so execution falls through to `findByIndex(block.number())` with `number = 0`: [4](#0-3) 

**The two repository methods execute fundamentally different SQL** — `RecordFileRepository.java` lines 24 and 28:
- `findEarliest()`: `SELECT * FROM record_file ORDER BY index ASC LIMIT 1` — returns the row with the **lowest** index, whatever that value is.
- `findByIndex(0)`: `SELECT r FROM RecordFile r WHERE r.index = 0` — returns a row only if `index` exactly equals 0. [5](#0-4) 

**`BlockNumberMigration` shifts all indices** — `BlockNumberMigration.java` lines 24–26 hard-code the correct genesis block numbers (mainnet: `34305852`, testnet: `22384256`) and apply an offset to every row via `updateIndex(offset)`. After migration, no row has `index = 0` on either network: [6](#0-5) 

**Root cause:** `BlockType` is a Java `record`; its auto-generated `equals()` compares all components, but `==` checks object identity. The `EARLIEST` singleton is only returned when the literal string `"earliest"` is parsed via `blockTypeForTag()`. Any numeric path (hex or decimal) creates a fresh object, so `==` always fails for those inputs. [7](#0-6) 

## Impact Explanation
Any JSON-RPC call (`eth_call`, `eth_getBalance`, `eth_getCode`, etc.) that specifies block `"0x00"`, `"0x0"`, or `"0"` will receive a block-not-found error on mainnet and testnet, even though the Ethereum JSON-RPC specification treats block number 0 as equivalent to `"earliest"`. Callers following the Ethereum spec will get unexpected failures, and any tooling or contract that queries historical state at block 0 will silently receive no data. No funds are directly at risk.

## Likelihood Explanation
The trigger requires no privileges — any JSON-RPC client can submit `eth_call` with `"blockNumber": "0x00"`. The input is valid per the Ethereum spec and passes all input validation in `BlockType.of()`. The condition (genesis index ≠ 0) is permanently true on mainnet and testnet after `BlockNumberMigration` runs. The bug is therefore reliably and repeatably triggerable by any external user on every production deployment.

## Recommendation
Replace the reference equality checks in `findByBlockType()` with `.equals()` comparisons, or — more robustly — compare by `number` value directly:

```java
// Option A: use .equals()
if (BlockType.EARLIEST.equals(block)) {
    return recordFileRepository.findEarliest();
} else if (BlockType.LATEST.equals(block)) {
    return recordFileRepository.findLatest();
}
```

Or, since `BlockType` is a record with a well-defined `number` field:

```java
// Option B: compare by number semantics
if (block.number() == 0L && !block.isHash()) {
    return recordFileRepository.findEarliest();
}
```

The `blockTypeForTag()` method already correctly returns the singleton for the string `"earliest"`, so no change is needed there. [4](#0-3) 

## Proof of Concept
```
POST /api/v1/contracts/call
{
  "from": "0x...",
  "to":   "0x...",
  "data": "0x...",
  "blockNumber": "0x00"   // or "0x0" or "0"
}
```

1. `BlockTypeDeserializer.deserialize()` calls `BlockType.of("0x00")`.
2. `BlockType.of()` matches `GROUP_HEX_NUM`, returns `new BlockType("00", 0L)` — a new object.
3. `findByBlockType(block)`: `block == BlockType.EARLIEST` → `false`; `block == BlockType.LATEST` → `false`; `block.isHash()` → `false`.
4. `recordFileRepository.findByIndex(0)` executes `WHERE r.index = 0`.
5. On mainnet/testnet (post-`BlockNumberMigration`), no such row exists → `Optional.empty()`.
6. The caller receives a block-not-found error, while `"earliest"` for the same request would succeed.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L29-29)
```java
    public static final BlockType EARLIEST = new BlockType("earliest", 0L);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L84-90)
```java
    private static BlockType blockTypeForTag(String tag) {
        return switch (tag) {
            case "earliest" -> EARLIEST;
            case "finalized", "latest", "pending", "safe" -> LATEST;
            default -> throw new IllegalStateException("Unexpected block tag: " + tag);
        };
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L23-29)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST, unless = "#result == null")
    @Query(value = "select * from record_file order by index asc limit 1", nativeQuery = true)
    Optional<RecordFile> findEarliest();

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
