All key claims are verifiable in the code. Let me confirm each one before rendering a verdict.

**Claim 1 — `LATEST` sentinel definition:** [1](#0-0) 
Confirmed: `LATEST = new BlockType("latest", Long.MAX_VALUE)`.

**Claim 2 — hex-number branch creates a new instance:** [2](#0-1) 
Confirmed: `GROUP_HEX_NUM` captures the digits after `0x`, so `"0x7fffffffffffffff"` → `hexNum = "7fffffffffffffff"` → `new BlockType("7fffffffffffffff", Long.MAX_VALUE)`. This is structurally distinct from `LATEST` (`name` differs).

**Claim 3 — test suite documents this as accepted input:** [3](#0-2) 
Confirmed: `"0x7fffffffffffffff," + MAX_VALUE` is in the `valid()` CSV source, and the test explicitly asserts `name = "7fffffffffffffff"` (not `"latest"`), confirming the new instance is intentionally distinct.

**Claim 4 — reference-equality guard in `findByBlockType`:** [4](#0-3) 
Confirmed: `block == BlockType.LATEST` fails for the new instance; execution falls through to `findByIndex(Long.MAX_VALUE)`, which returns `Optional.empty()`.

**Claim 5 — downstream effect:** [5](#0-4) 
`orElseThrow(BlockNumberNotFoundException::new)` is called, producing a 400 "Unknown block number" response.

**One material overstatement in the claim:** The report asserts callers "may execute the transaction against stale or zero-initialized EVM state." The actual code path throws `BlockNumberNotFoundException` before any EVM execution occurs — there is no silent fallback to incorrect state. The impact is a 400 error, not wrong-state execution.

---

Audit Report

## Title
LATEST Sentinel Collision: `0x7fffffffffffffff` Bypasses Reference-Equality Guard in `findByBlockType`, Returning Empty Optional

## Summary
`BlockType.of("0x7fffffffffffffff")` produces a new `BlockType` record with `name = "7fffffffffffffff"` and `number = Long.MAX_VALUE`. Because `findByBlockType` guards the `findLatest()` path with a reference-equality check (`block == BlockType.LATEST`), this new instance falls through to `findByIndex(Long.MAX_VALUE)`, which returns `Optional.empty()`. Any caller that passes `0x7fffffffffffffff` as a block parameter receives a `BlockNumberNotFoundException` (HTTP 400) instead of the latest block result.

## Finding Description

**Root cause — sentinel collision in `BlockType`:**

`LATEST` is defined as:
```java
public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
``` [6](#0-5) 

The hex-number branch of `BlockType.of()` captures the digits after `0x` (group 4) and constructs a new instance:
```java
final var hexNum = matcher.group(GROUP_HEX_NUM); // "7fffffffffffffff"
return new BlockType(hexNum, Long.parseLong(hexNum, 16)); // Long.MAX_VALUE
``` [2](#0-1) 

`Long.parseLong("7fffffffffffffff", 16)` returns `Long.MAX_VALUE` without overflow. The result is `new BlockType("7fffffffffffffff", Long.MAX_VALUE)` — a different object from `LATEST` because the `name` field differs. The test suite explicitly documents and accepts this behavior: [3](#0-2) 

**Bypass in `findByBlockType`:**

```java
} else if (block == BlockType.LATEST) {      // reference equality — fails for the new instance
    return recordFileRepository.findLatest();
}
return recordFileRepository.findByIndex(block.number()); // called with Long.MAX_VALUE
``` [7](#0-6) 

`findByIndex(Long.MAX_VALUE)` queries for a block with index `9223372036854775807`. No such block exists, so `Optional.empty()` is returned.

**Why existing checks are insufficient:**
- The `==` guard is reference equality, not a value/number check. Java records auto-generate `equals()` based on all fields; `LATEST.equals(new BlockType("7fffffffffffffff", MAX_VALUE))` is `false` because `name` differs.
- The `isHash()` guard uses `-1L` as sentinel and is unrelated.
- No numeric sentinel check (`block.number() == Long.MAX_VALUE`) is present.

## Impact Explanation
Any JSON-RPC endpoint that accepts a user-supplied block parameter (e.g., `eth_call`, `eth_getBalance`, `eth_getCode`, `eth_estimateGas`) and routes it through `BlockType.of()` → `findByBlockType()` will receive `Optional.empty()`. The `ContractCallService` calls `orElseThrow(BlockNumberNotFoundException::new)`: [5](#0-4) 

This produces an HTTP 400 "Unknown block number" response for every request using `0x7fffffffffffffff` as the block parameter, regardless of whether the caller intended it to mean "latest." No EVM execution occurs and no incorrect state is returned — the request simply fails. The impact is a targeted, per-request denial of service for any caller using this value.

## Likelihood Explanation
`0x7fffffffffffffff` is a syntactically valid Ethereum hex block number accepted by every standard JSON-RPC client library. Any user who knows (or discovers by fuzzing) that `Long.MAX_VALUE` is the internal LATEST sentinel can reproduce this deterministically on every request. No rate-limiting or authentication is required. The attack is stateless and repeatable.

## Recommendation
Replace the reference-equality guard in `findByBlockType` with a numeric sentinel check:

```java
} else if (block == BlockType.LATEST || block.number() == Long.MAX_VALUE) {
    return recordFileRepository.findLatest();
}
``` [8](#0-7) 

Alternatively, modify `BlockType.of()` to return the `LATEST` singleton whenever the parsed numeric value equals `Long.MAX_VALUE`, regardless of the input format:

```java
final var hexNum = matcher.group(GROUP_HEX_NUM);
if (hexNum != null) {
    long val = Long.parseLong(hexNum, 16);
    if (val == Long.MAX_VALUE) return LATEST;
    return new BlockType(hexNum, val);
}
``` [9](#0-8) 

The same fix should be applied to the decimal branch for consistency (input `"9223372036854775807"` has the same collision).

## Proof of Concept
```java
// Demonstrates the sentinel collision
BlockType colliding = BlockType.of("0x7fffffffffffffff");
assert colliding != BlockType.LATEST;           // different object
assert colliding.number() == Long.MAX_VALUE;    // same number as LATEST
assert colliding.name().equals("7fffffffffffffff"); // different name

// findByBlockType falls through to findByIndex(Long.MAX_VALUE)
// which returns Optional.empty() → BlockNumberNotFoundException → HTTP 400
```

Equivalent JSON-RPC request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_call",
  "params": [{ "to": "0x...", "data": "0x..." }, "0x7fffffffffffffff"],
  "id": 1
}
```
Expected (correct): same result as `"latest"`.
Actual: HTTP 400 `{"status":"Bad Request","message":"Unknown block number"}`.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L29-30)
```java
    public static final BlockType EARLIEST = new BlockType("earliest", 0L);
    public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L73-80)
```java
        final var hexNum = matcher.group(GROUP_HEX_NUM);
        if (hexNum != null) {
            try {
                return new BlockType(hexNum, Long.parseLong(hexNum, 16));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Hex value out of range for block: " + value, e);
            }
        }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/viewmodel/BlockTypeTest.java (L39-49)
```java
        "0x7fffffffffffffff," + MAX_VALUE,
        "earliest,0",
        "EARLIEST,0",
        "latest," + MAX_VALUE
    })
    @ParameterizedTest
    void valid(String value, long number) {
        final var blockType = BlockType.of(value);
        final var expectedName =
                StringUtils.isNotEmpty(value) ? value.toLowerCase(Locale.ROOT).replace(HEX_PREFIX, "") : "latest";
        assertThat(blockType).isNotNull().returns(expectedName, BlockType::name).returns(number, BlockType::number);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L103-104)
```java
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));
```
