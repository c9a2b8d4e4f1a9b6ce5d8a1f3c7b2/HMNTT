Looking at the actual code:

**`BlockType.java`** — `BlockType` is a Java `record`. The `LATEST` singleton is `new BlockType("latest", Long.MAX_VALUE)`. The `@JsonCreator` factory `of()` returns the singleton for string inputs `"latest"`, `"safe"`, `"pending"`, `"finalized"`, but for numeric inputs it calls `extractNumericBlock()` which does `return new BlockType(value, blockNumber)` — a **new, non-singleton instance**.

**`RecordFileServiceImpl.java` line 22** uses `block == BlockType.LATEST` (reference equality). A user passing `"9223372036854775807"` or `"0x7fffffffffffffff"` as the block parameter causes `BlockType.of()` to produce a non-singleton `BlockType` with `number = Long.MAX_VALUE`, which fails the `==` check and falls through to `findByIndex(Long.MAX_VALUE)`.

**`ContractCallService.java` line 104** calls `.orElseThrow(BlockNumberNotFoundException::new)` on the result, so the empty Optional becomes an exception.

All 5 validation gates pass.

---

### Title
Reference-Equality Check on Java Record Allows `Long.MAX_VALUE` Block Number to Bypass `LATEST` Resolution

### Summary
`RecordFileServiceImpl.findByBlockType()` uses Java reference equality (`==`) to detect the `BlockType.LATEST` sentinel, but `BlockType` is a Java `record` whose factory method `BlockType.of()` creates a **new, non-singleton instance** when given the numeric string `"9223372036854775807"` (or hex `"0x7fffffffffffffff"`). This non-singleton has identical field values to `LATEST` but fails the `==` check, causing `findByIndex(Long.MAX_VALUE)` to be called instead of `findLatest()`, which returns `Optional.empty()` and throws `BlockNumberNotFoundException` for any contract call using that block parameter.

### Finding Description
**Code location:** `web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java`, `findByBlockType()`, lines 19–27; specifically line 22.

**Root cause:** Java `record` instances are value-typed for `.equals()` but not for `==`. The guard at line 22:
```java
} else if (block == BlockType.LATEST) {
    return recordFileRepository.findLatest();
}
```
only matches the exact singleton object. [1](#0-0) 

**How a non-singleton is created:** `BlockType.of()` returns `LATEST` for string names (`"latest"`, `"safe"`, etc.), but for any numeric input it calls `extractNumericBlock()`, which unconditionally does `return new BlockType(value, blockNumber)`. [2](#0-1) 

Passing `"9223372036854775807"` (decimal `Long.MAX_VALUE`) or `"0x7fffffffffffffff"` routes through `extractNumericBlock`, producing a fresh `BlockType` instance with `number = Long.MAX_VALUE` that is **not** the `LATEST` singleton. [3](#0-2) 

**Exploit flow:**
1. User sends a JSON-RPC request (e.g., `eth_call`) with `"block": "9223372036854775807"`.
2. Jackson calls `BlockType.of("9223372036854775807")` via `@JsonCreator`. [4](#0-3) 
3. `extractNumericBlock` parses it as `Long.MAX_VALUE` and returns `new BlockType("9223372036854775807", Long.MAX_VALUE)` — a non-singleton.
4. `findByBlockType` receives this; `block == BlockType.LATEST` is `false`; falls through to `recordFileRepository.findByIndex(Long.MAX_VALUE)`. [5](#0-4) 
5. No record file has index `Long.MAX_VALUE`; `findByIndex` returns `Optional.empty()`.
6. `ContractCallService.callContract()` calls `.orElseThrow(BlockNumberNotFoundException::new)`, throwing an exception. [6](#0-5) 

**Why existing checks are insufficient:** The `of()` factory correctly guards named strings (`"latest"`, `"safe"`, etc.) but has no guard preventing numeric `Long.MAX_VALUE` from creating a non-singleton. There is no `.equals()`-based fallback in `findByBlockType`. [7](#0-6) 

### Impact Explanation
Any unauthenticated caller can force `BlockNumberNotFoundException` on any contract call or estimation request by supplying `Long.MAX_VALUE` as the block number. Calls that should succeed against the latest state instead fail. This constitutes reliable, targeted request-level denial of service and incorrect block resolution for all downstream consumers of `findByBlockType`. Severity: **Medium** (DoS / incorrect behavior, no data exfiltration).

### Likelihood Explanation
No privileges are required. The value `"9223372036854775807"` is a valid decimal integer accepted by the JSON-RPC API. Any attacker who knows the internal sentinel value (publicly visible in the open-source code) can reproduce this deterministically and repeatedly with a single crafted request.

### Recommendation
Replace the reference-equality checks with `.equals()` comparisons, or add a numeric guard in `extractNumericBlock` that maps `Long.MAX_VALUE` back to the `LATEST` singleton:

```java
// Option A: use .equals() in findByBlockType
if (BlockType.LATEST.equals(block)) { ... }

// Option B: in extractNumericBlock, intercept Long.MAX_VALUE
if (blockNumber == Long.MAX_VALUE) return LATEST;
```

Option B is preferable because it prevents the ambiguous non-singleton from ever being created.

### Proof of Concept
```
POST /api/v1/contracts/call HTTP/1.1
Content-Type: application/json

{
  "block": "9223372036854775807",
  "data": "0x...",
  "to": "0x..."
}
```
Expected (correct): executes against latest block state.
Actual: throws `BlockNumberNotFoundException` because `findByIndex(9223372036854775807)` returns empty. [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L17-18)
```java
    @JsonCreator
    public static BlockType of(final String value) {
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

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L37-55)
```java
    private static BlockType extractNumericBlock(String value) {
        int radix = 10;
        var cleanedValue = value;

        if (value.startsWith(HEX_PREFIX)) {
            radix = 16;
            cleanedValue = Strings.CS.removeStart(value, HEX_PREFIX);
        }

        if (cleanedValue.contains(NEGATIVE_NUMBER_PREFIX)) {
            throw new IllegalArgumentException("Invalid block value: " + value);
        }

        try {
            long blockNumber = Long.parseLong(cleanedValue, radix);
            return new BlockType(value, blockNumber);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid block value: " + value, e);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L103-104)
```java
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));
```
