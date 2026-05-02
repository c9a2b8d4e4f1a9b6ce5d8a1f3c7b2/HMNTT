Now I have all the code needed to fully analyze this claim. Let me verify the exact behavior:

### Title
Reference Equality Bypass on `BlockType.LATEST` via Decimal `Long.MAX_VALUE` String Causes Silent Lookup Failure

### Summary
`RecordFileServiceImpl.findByBlockType()` uses Java reference equality (`==`) to detect the `LATEST` sentinel, but `BlockType.of("9223372036854775807")` — the decimal string of `Long.MAX_VALUE` — legally parses and constructs a **new** `BlockType` instance with `number=Long.MAX_VALUE` that is structurally identical to `BlockType.LATEST` yet fails the `==` check. The call then falls through to `recordFileRepository.findByIndex(Long.MAX_VALUE)`, which finds no real block and returns `Optional.empty()`, silently denying the caller the latest block data.

### Finding Description

**Root cause — `BlockType.of()` decimal branch:**

In `web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java`, the regex `GROUP_DECIMAL` accepts `\d{1,20}`, which covers all 19-digit strings including `"9223372036854775807"` (`Long.MAX_VALUE`). [1](#0-0) 

`Long.parseLong("9223372036854775807", 10)` succeeds (it is exactly `Long.MAX_VALUE`), so the method returns:
```java
new BlockType("9223372036854775807", Long.MAX_VALUE)   // a fresh heap object
``` [2](#0-1) 

The `LATEST` constant is:
```java
public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
``` [3](#0-2) 

**Root cause — reference equality in `findByBlockType()`:**

`RecordFileServiceImpl` guards the `findLatest()` path with `==`:
```java
} else if (block == BlockType.LATEST) {
    return recordFileRepository.findLatest();
``` [4](#0-3) 

Because `BlockType` is a Java `record`, the compiler auto-generates a value-based `equals()`, but the code never calls it — it uses `==`. The freshly constructed instance from the decimal path is a different object reference, so the guard is bypassed.

**Exploit flow:**

1. Attacker sends any API request that accepts a block parameter (e.g., `eth_getBlockByNumber`, `eth_call`, contract simulation) with block value `"9223372036854775807"`.
2. `BlockType.of("9223372036854775807")` is invoked (it is `@JsonCreator`-annotated, so it is called during JSON deserialization).
3. The decimal branch fires, returning `new BlockType("9223372036854775807", Long.MAX_VALUE)`.
4. In `findByBlockType`, `block == BlockType.EARLIEST` → false; `block == BlockType.LATEST` → false (different reference); `block.isHash()` → false (`number != -1`).
5. Falls through to `recordFileRepository.findByIndex(Long.MAX_VALUE)`. [5](#0-4) 
6. The JPA query `where r.index = 9223372036854775807` matches nothing; returns `Optional.empty()`. [6](#0-5) 

**Why existing checks are insufficient:**

- The `blockTypeForTag` switch correctly returns the `LATEST` singleton for string tags (`"latest"`, `"safe"`, etc.), but the decimal numeric path always allocates a new object. [7](#0-6) 
- There is no upper-bound validation on the decimal value before constructing the `BlockType`; `Long.MAX_VALUE` is a valid `long`, so no `NumberFormatException` is thrown.
- The `isHash()` guard only checks `number == -1`, so it does not intercept this case. [8](#0-7) 

### Impact Explanation

Any caller of `findByBlockType` that receives `Optional.empty()` when it expected the latest block will either throw an exception, return an HTTP error, or silently serve stale/missing data to the end user. Concretely:

- `ContractCallService` and similar services that use `findByBlockType` to resolve the execution context will fail for every request that passes this block number, effectively denying service for those calls.
- Because `Long.MAX_VALUE` will never match a real block index, the failure is deterministic and 100% reproducible.
- No funds are directly at risk, but transaction history lookups and contract simulations against "latest" state are disrupted for any request using this value.

### Likelihood Explanation

- **No authentication required.** Any external caller of the JSON-RPC or REST API can supply a block number string.
- **Trivially discoverable.** The value `Long.MAX_VALUE` is a well-known Java constant; an attacker fuzzing block number inputs with boundary values will find it immediately.
- **Repeatable on demand.** The bug is deterministic — every request with this exact string triggers the bypass.

### Recommendation

Replace reference equality with value-based equality in `findByBlockType`, or intercept the sentinel value in `BlockType.of()`:

**Option A — fix `findByBlockType` (preferred):**
```java
} else if (BlockType.LATEST.equals(block)) {   // use record's auto-generated equals()
    return recordFileRepository.findLatest();
```

**Option B — fix `BlockType.of()` decimal branch:**
```java
long num = Long.parseLong(decimal, 10);
if (num == Long.MAX_VALUE) return LATEST;      // return the singleton
return new BlockType(value, num);
```

**Option C — add an upper-bound guard:**
Reject any decimal block number ≥ some practical maximum (e.g., current chain height + safety margin) before constructing a `BlockType`.

### Proof of Concept

```
# Assuming a standard eth_getBlockByNumber JSON-RPC endpoint:
curl -X POST http://<mirror-node-web3>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{
    "block": "9223372036854775807",
    "data": "0x...",
    "to": "0x..."
  }'

# Expected (correct) behavior: resolves to the latest block and executes.
# Actual behavior: findByBlockType returns Optional.empty(),
#                  causing a lookup failure / error response.
```

Reproduce in a unit test:
```java
BlockType b = BlockType.of("9223372036854775807");
assert b != BlockType.LATEST;          // true — different reference
assert b.number() == Long.MAX_VALUE;   // true — same numeric value
// RecordFileServiceImpl.findByBlockType(b) calls findByIndex(Long.MAX_VALUE)
// instead of findLatest(), returning Optional.empty().
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L18-22)
```java
    private static final Pattern BLOCK_PATTERN = Pattern.compile("^(?:" + "(earliest|finalized|latest|pending|safe)"
            + "|(\\d{1,20})"
            + "|0x([0-9a-f]{64}|[0-9a-f]{96})"
            + "|0x([0-9a-f]{1,16})"
            + ")$");
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L30-30)
```java
    public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L38-40)
```java
    public boolean isHash() {
        return number == BLOCK_HASH_SENTINEL;
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L27-29)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
    @Query("select r from RecordFile r where r.index = ?1")
    Optional<RecordFile> findByIndex(long index);
```
