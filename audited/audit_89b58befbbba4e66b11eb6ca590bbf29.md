### Title
Reference Equality Bypass in `findByBlockType()` Causes `0x00` Block Parameter to Skip `findEarliest()` and Return Empty on Non-Zero-Genesis Networks

### Summary
`RecordFileServiceImpl.findByBlockType()` uses Java reference equality (`==`) to detect `BlockType.EARLIEST`, but `BlockType.of("0x00")` (and any other numeric-zero input like `"0x0"` or `"0"`) constructs a **new** `BlockType("00", 0L)` instance that is never the same reference as the static `BlockType.EARLIEST = new BlockType("earliest", 0L)`. The check silently falls through to `recordFileRepository.findByIndex(0)`, which on Hedera mainnet and testnet — where the genesis block index is `34305852` and `22384256` respectively — returns `Optional.empty()` instead of the actual earliest block, causing `eth_call` at block `0x00` to fail or return incorrect state.

### Finding Description

**Code path:**

`BlockType.of("0x00")` in `BlockType.java` lines 73–79: [1](#0-0) 

The regex group `GROUP_HEX_NUM` (`0x([0-9a-f]{1,16})`) captures `"00"` from `"0x00"`, then executes:
```java
return new BlockType("00", Long.parseLong("00", 16)); // → new BlockType("00", 0L)
```

This is a **new heap object**, not the static constant: [2](#0-1) 

In `findByBlockType()`, the guard uses `==` (reference equality): [3](#0-2) 

Since `new BlockType("00", 0L) != BlockType.EARLIEST` by reference, and `isHash()` is false (`0 != -1`), execution falls to `findByIndex(0)`.

**The two queries diverge:**

- `findEarliest()`: `select * from record_file order by index asc limit 1` — returns the record with the **lowest index**, whatever it is. [4](#0-3) 

- `findByIndex(0)`: `select r from RecordFile r where r.index = ?1` — returns the record with index **exactly 0**. [5](#0-4) 

**On Hedera mainnet and testnet, the genesis block index is NOT 0.** `BlockNumberMigration` hard-codes the correct genesis block numbers: [6](#0-5) 

Mainnet genesis index = `34305852`, testnet = `22384256`. No record with `index = 0` exists, so `findByIndex(0)` returns `Optional.empty()`.

**Root cause:** The failed assumption is that `BlockType.of()` always returns one of the static singletons for numeric zero. It does not — it always allocates a new instance for any numeric input, including `"0"`, `"0x0"`, `"0x00"`, etc.

### Impact Explanation
Any `eth_call` (or `eth_getBalance`, `eth_getCode`, etc.) submitted with block parameter `"0x00"` (or `"0x0"`, or decimal `"0"`) on a mainnet/testnet mirror node will fail to resolve the genesis block state. The caller receives an empty/error response instead of the correct earliest-block state. This constitutes unintended smart contract simulation behavior: a contract call that should execute against genesis state instead returns a block-not-found error, potentially breaking dApps or tooling that canonically use `0x0` to mean "genesis block." No funds are directly at risk since this is a read-only path.

### Likelihood Explanation
Any unprivileged external user can trigger this with a single standard JSON-RPC call. No authentication, no special role, no prior knowledge of internal state is required. The input `"0x00"` is a valid Ethereum block parameter per the JSON-RPC spec and is commonly used by clients and libraries. The bug is deterministic and 100% reproducible on any mainnet or testnet mirror node deployment.

### Recommendation
Replace the reference equality checks in `findByBlockType()` with semantic equality. The cleanest fix is to compare by `number` for numeric block types:

```java
public Optional<RecordFile> findByBlockType(BlockType block) {
    if (block == BlockType.EARLIEST || (!block.isHash() && block.number() == 0)) {
        return recordFileRepository.findEarliest();
    } else if (block == BlockType.LATEST || (!block.isHash() && block.number() == Long.MAX_VALUE)) {
        return recordFileRepository.findLatest();
    } else if (block.isHash()) {
        return recordFileRepository.findByHash(block.name());
    }
    return recordFileRepository.findByIndex(block.number());
}
```

Alternatively, `BlockType.of()` should return the `EARLIEST` singleton whenever the parsed numeric value is 0 (and `LATEST` for `Long.MAX_VALUE`), so the `==` checks remain valid.

### Proof of Concept

**Precondition:** A Hiero mirror node connected to mainnet or testnet (genesis block index ≠ 0).

**Steps:**

1. Send a standard JSON-RPC request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_call",
  "params": [{"to": "0x0000000000000000000000000000000000000001", "data": "0x"}, "0x00"],
  "id": 1
}
```

2. Internally, `BlockType.of("0x00")` creates `new BlockType("00", 0L)`.

3. In `findByBlockType()`, `block == BlockType.EARLIEST` is `false` (different references).

4. `findByIndex(0)` executes `SELECT ... WHERE index = 0` — no row exists on mainnet.

5. The call returns an error or empty block response.

**Contrast:** The same call with `"earliest"` correctly invokes `findEarliest()` and returns the genesis block state.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L29-30)
```java
    public static final BlockType EARLIEST = new BlockType("earliest", 0L);
    public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L20-28)
```java
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
            return recordFileRepository.findLatest();
        } else if (block.isHash()) {
            return recordFileRepository.findByHash(block.name());
        }

        return recordFileRepository.findByIndex(block.number());
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
