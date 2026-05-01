### Title
Reference Equality Bypass: Numeric `Long.MAX_VALUE` Block Number Causes `BlockNumberNotFoundException` Instead of Latest-Block Behavior

### Summary
`RecordFileServiceImpl.findByBlockType()` uses Java reference equality (`==`) to detect `BlockType.LATEST`, but `BlockType.of("9223372036854775807")` (Long.MAX_VALUE as a decimal string) creates a **new** `BlockType` instance with `number=Long.MAX_VALUE` that is not the `LATEST` singleton. This causes the method to call `findByIndex(Long.MAX_VALUE)`, which returns empty, triggering `BlockNumberNotFoundException` and failing any smart contract call that uses this block parameter.

### Finding Description

**Root cause — reference equality in `RecordFileServiceImpl`:** [1](#0-0) 

Lines 20 and 22 use `==` (reference equality). `BlockType.LATEST` is a specific singleton: [2](#0-1) 

When a user passes the string `"9223372036854775807"`, `BlockType.of()` does not match any named case in the switch: [3](#0-2) 

It falls through to `extractNumericBlock()`, which successfully parses `Long.MAX_VALUE` and returns `new BlockType("9223372036854775807", Long.MAX_VALUE)` — a **new heap object**, not the `LATEST` singleton: [4](#0-3) 

Back in `findByBlockType`, both `==` checks fail, so execution reaches: [5](#0-4) 

`findByIndex(Long.MAX_VALUE)` queries the DB for a record file with `index = 9223372036854775807`, which never exists, returning `Optional.empty()`.

**Exception propagation — `ContractCallService`:** [6](#0-5) 

The `orElseThrow(BlockNumberNotFoundException::new)` fires, aborting the smart contract call.

### Impact Explanation
Any EVM `eth_call` or `eth_estimateGas` request that supplies `"9223372036854775807"` (or `"0x7fffffffffffffff"`) as the block parameter will receive a `BlockNumberNotFoundException` (HTTP 400 / "Unknown block number") instead of executing against the latest state. This is a denial-of-service against a specific, semantically valid block tag value. Because `Long.MAX_VALUE` is the internal sentinel for "latest," the mismatch can also confuse downstream logic that inspects `block.number()`.

### Likelihood Explanation
No authentication or special privilege is required. Any external caller of the JSON-RPC API can trigger this by passing the decimal string `"9223372036854775807"` as the `block` parameter. The value is a valid `long`, passes all input validation in `extractNumericBlock`, and is trivially discoverable by anyone who reads the open-source code or notices that `0x7fffffffffffffff` is the hex equivalent of `Long.MAX_VALUE`. The attack is fully repeatable and deterministic.

### Recommendation
Replace reference equality with value-based equality in `RecordFileServiceImpl.findByBlockType()`. The simplest fix is to compare by `number`:

```java
@Override
public Optional<RecordFile> findByBlockType(BlockType block) {
    if (block.number() == BlockType.EARLIEST.number() && block.number() == 0L) {
        return recordFileRepository.findEarliest();
    } else if (block.number() == Long.MAX_VALUE) {   // covers LATEST and numeric equivalent
        return recordFileRepository.findLatest();
    }
    return recordFileRepository.findByIndex(block.number());
}
```

Alternatively, override `equals` in the `BlockType` record to compare by `number` only, or add an explicit check in `BlockType.of()` to return the `LATEST` singleton when the parsed numeric value equals `Long.MAX_VALUE`:

```java
long blockNumber = Long.parseLong(cleanedValue, radix);
if (blockNumber == Long.MAX_VALUE) return LATEST;   // return singleton
return new BlockType(value, blockNumber);
```

### Proof of Concept

1. Start the mirror-node web3 service.
2. Send an `eth_call` JSON-RPC request with the block tag set to the decimal string `"9223372036854775807"`:
   ```json
   {
     "jsonrpc": "2.0",
     "method": "eth_call",
     "params": [{"to": "0x...", "data": "0x..."}, "9223372036854775807"],
     "id": 1
   }
   ```
3. `BlockType.of("9223372036854775807")` creates a new `BlockType` instance (not `LATEST` singleton).
4. `RecordFileServiceImpl.findByBlockType()` reference-equality checks both fail.
5. `recordFileRepository.findByIndex(9223372036854775807L)` returns `Optional.empty()`.
6. `orElseThrow(BlockNumberNotFoundException::new)` fires.
7. The caller receives an error response ("Unknown block number") instead of the result of executing against the latest block.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-27)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
            return recordFileRepository.findLatest();
        }

        return recordFileRepository.findByIndex(block.number());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L12-12)
```java
    public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L24-34)
```java
        switch (blockTypeName) {
            case "earliest" -> {
                return EARLIEST;
            }
            case "latest", "safe", "pending", "finalized" -> {
                return LATEST;
            }
            default -> {
                return extractNumericBlock(value);
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L50-52)
```java
        try {
            long blockNumber = Long.parseLong(cleanedValue, radix);
            return new BlockType(value, blockNumber);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L103-104)
```java
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));
```
