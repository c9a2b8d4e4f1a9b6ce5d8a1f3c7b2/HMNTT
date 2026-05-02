All code references in the report have been verified against the actual source. Here is the result:

---

Audit Report

## Title
`BlockType.of("0x0")` Bypasses `EARLIEST` Identity Check via Reference Inequality, Routing to `findByIndex(0)` Instead of `findEarliest()`

## Summary
`RecordFileServiceImpl.findByBlockType()` guards the `EARLIEST` path with Java reference equality (`==`). `BlockType.of("0x0")` always allocates a fresh `BlockType` instance whose `name` field is `"0"`, not `"earliest"`, so it can never satisfy the `==` guard. The call silently falls through to `findByIndex(0)`, which executes a semantically different SQL query than `findEarliest()`. In any deployment where the earliest ingested record file does not carry `index = 0`, the lookup returns `Optional.empty()` while `findEarliest()` would return a valid block.

## Finding Description

**Root cause — `BlockType.java`**

The `EARLIEST` singleton is declared at line 29: [1](#0-0) 

The hex-number branch of `BlockType.of()` at lines 73–76 always allocates a new instance: [2](#0-1) 

For input `"0x0"`, the regex capture group `GROUP_HEX_NUM` yields `"0"` (the `0x` prefix is consumed by the pattern), producing `new BlockType("0", 0L)`. `BlockType` is a Java `record`; its auto-generated `equals()` compares both `name` and `number`. `EARLIEST` has `name="earliest"`, the new instance has `name="0"` — they are permanently distinguishable by both `==` and `.equals()`.

The decimal path (`BlockType.of("0")`) has the same problem: lines 59–66 return `new BlockType("0", 0L)`. [3](#0-2) 

**Dispatch logic — `RecordFileServiceImpl.java` lines 20–28**

The guard uses `==`: [4](#0-3) 

For `BlockType.of("0x0")`:
- `block == BlockType.EARLIEST` → `false` (different instance, different `name`)
- `block == BlockType.LATEST` → `false`
- `block.isHash()` → `false` (`number = 0`, not `BLOCK_HASH_SENTINEL = -1`)
- Falls through to `recordFileRepository.findByIndex(0)`

**Query difference — `RecordFileRepository.java`**

| Method | SQL |
|---|---|
| `findEarliest()` | `SELECT * FROM record_file ORDER BY index ASC LIMIT 1` |
| `findByIndex(0)` | `SELECT r FROM RecordFile r WHERE r.index = 0` | [5](#0-4) 

`findEarliest()` returns the record with the minimum index regardless of its value. `findByIndex(0)` returns a record only if one with `index = 0` exists.

**Cache split**

The two methods use different Spring cache managers (`CACHE_MANAGER_RECORD_FILE_EARLIEST` vs `CACHE_MANAGER_RECORD_FILE_INDEX`), so a warm `findEarliest()` cache is never consulted for `"0x0"` requests, and vice-versa — a cache-coherence split for what should be the same logical block. [5](#0-4) 

**Test coverage gap**

The existing test `testFindByBlockTypeEarliest` only exercises `BlockType.EARLIEST` directly; no test covers `BlockType.of("0x0")` or `BlockType.of("0")` routed through `findByBlockType`. [6](#0-5) 

## Impact Explanation
Any caller submitting a JSON-RPC method (`eth_getBalance`, `eth_call`, etc.) with `blockParam = "0x0"` or `blockParam = "0"` is routed to `findByIndex(0)`. In any environment where the genesis record file does not carry `index = 0` (partial mirror sync, testnet with non-zero start index), the lookup returns `Optional.empty()`, causing the RPC layer to treat the block as non-existent. Smart contract simulation then either aborts with a block-not-found error or falls back to an unintended default context, producing results inconsistent with what `"earliest"` would return. No funds are directly at risk, but contract state reads and simulations are silently wrong or unavailable.

## Likelihood Explanation
The trigger requires only a valid JSON-RPC call with `"0x0"` as the block parameter — no authentication, no special role, no on-chain transaction. Any public-facing mirror-node JSON-RPC endpoint is reachable by any internet user. The condition is reproducible deterministically. The only prerequisite limiting impact is whether the deployment's earliest block has `index = 0`; in standard full-sync Hedera deployments it does, reducing the empty-result scenario to partial-sync or non-standard deployments, but the cache-split and semantic divergence exist universally.

## Recommendation
Replace the reference-equality guards in `RecordFileServiceImpl.findByBlockType()` with value-based equivalence. The cleanest fix is to normalize numeric-zero inputs to the `EARLIEST` singleton inside `BlockType.of()`:

```java
// In BlockType.of(), hex-number branch:
final var hexNum = matcher.group(GROUP_HEX_NUM);
if (hexNum != null) {
    long num = Long.parseLong(hexNum, 16);
    return num == 0L ? EARLIEST : new BlockType(hexNum, num);
}

// Similarly for the decimal branch:
final var decimal = matcher.group(GROUP_DECIMAL);
if (decimal != null) {
    long num = Long.parseLong(decimal, 10);
    return num == 0L ? EARLIEST : new BlockType(value, num);
}
```

Alternatively, change the dispatch in `RecordFileServiceImpl` to use `.equals()` instead of `==`, and add a test covering `BlockType.of("0x0")` and `BlockType.of("0")` routed through `findByBlockType` with a non-zero-indexed earliest block.

## Proof of Concept
1. Start a mirror node with partial sync so the earliest ingested block has `index = 5` (not `0`).
2. Call `eth_getBalance` with `"blockParam": "0x0"`.
3. `BlockType.of("0x0")` returns `new BlockType("0", 0L)`.
4. `RecordFileServiceImpl.findByBlockType()` falls through to `recordFileRepository.findByIndex(0)`.
5. `findByIndex(0)` executes `WHERE r.index = 0` — no row exists — returns `Optional.empty()`.
6. The RPC layer returns a block-not-found error or incorrect default context.
7. Repeat with `"blockParam": "earliest"` — `BlockType.EARLIEST` is returned directly, `findEarliest()` executes `ORDER BY index ASC LIMIT 1`, returns the block at `index = 5` correctly.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L29-29)
```java
    public static final BlockType EARLIEST = new BlockType("earliest", 0L);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L59-66)
```java
        final var decimal = matcher.group(GROUP_DECIMAL);
        if (decimal != null) {
            try {
                return new BlockType(value, Long.parseLong(decimal, 10));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Decimal value out of range for block: " + value, e);
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L73-77)
```java
        final var hexNum = matcher.group(GROUP_HEX_NUM);
        if (hexNum != null) {
            try {
                return new BlockType(hexNum, Long.parseLong(hexNum, 16));
            } catch (NumberFormatException e) {
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

**File:** web3/src/test/java/org/hiero/mirror/web3/service/RecordFileServiceTest.java (L28-34)
```java
    void testFindByBlockTypeEarliest() {
        final var genesisRecordFile =
                domainBuilder.recordFile().customize(f -> f.index(0L)).persist();
        domainBuilder.recordFile().customize(f -> f.index(1L)).persist();
        domainBuilder.recordFile().customize(f -> f.index(2L)).persist();
        assertThat(recordFileService.findByBlockType(BlockType.EARLIEST)).contains(genesisRecordFile);
    }
```
