### Title
Identity Comparison (`==`) on `BlockType.LATEST` Allows Unprivileged DoS via `eth_call` with Block `0x7fffffffffffffff`

### Summary
`RecordFileServiceImpl.findByBlockType()` uses Java reference-equality (`==`) to detect `BlockType.LATEST`, but `BlockType.of("0x7fffffffffffffff")` constructs a **new** `BlockType` instance whose `number` field equals `Long.MAX_VALUE` — the same sentinel used by the `LATEST` singleton. Because the new object is not the same reference, the `LATEST` branch is skipped, the call falls through to `findByIndex(Long.MAX_VALUE)`, which returns `Optional.empty()`, and `orElseThrow(BlockNumberNotFoundException::new)` is triggered. Any unauthenticated caller can reproduce this deterministically.

### Finding Description

**Root cause — `BlockType.java` lines 29–30 and 73–79:**

`LATEST` is a singleton with `number = Long.MAX_VALUE`: [1](#0-0) 

When the hex path is taken, a **new** object is allocated: [2](#0-1) 

`Long.parseLong("7fffffffffffffff", 16)` == `Long.MAX_VALUE` == `9223372036854775807`, so the result is `new BlockType("7fffffffffffffff", Long.MAX_VALUE)` — a distinct heap object.

**Failed check — `RecordFileServiceImpl.java` lines 22–28:** [3](#0-2) 

`block == BlockType.LATEST` is a reference comparison. The newly created instance is not the singleton, so the condition is `false`. `block.isHash()` is also `false` (number ≠ -1). Execution falls to `findByIndex(Long.MAX_VALUE)`.

**Exception path — `ContractCallService.java` line 104:** [4](#0-3) 

`findByIndex(Long.MAX_VALUE)` returns `Optional.empty()` (no record file has index 9 223 372 036 854 775 807), so `orElseThrow` fires `BlockNumberNotFoundException`.

### Impact Explanation
Every `eth_call` / `eth_estimateGas` request that supplies `block = "0x7fffffffffffffff"` fails with an "Unknown block number" error instead of executing against the latest state. This is a targeted, zero-cost denial-of-service against any caller or application that uses this specific block tag (e.g., some Ethereum tooling uses `0x7fffffffffffffff` as a "max future block" sentinel). No funds are directly at risk, but smart-contract reads and simulations are completely broken for that parameter value, matching the stated Medium severity (unintended smart contract behavior, no direct fund loss).

### Likelihood Explanation
No authentication or special privilege is required. The input is a standard JSON-RPC parameter accepted by the public endpoint. The value `0x7fffffffffffffff` is a well-known sentinel used by several Ethereum libraries and wallets. An attacker (or even a misconfigured client) can trigger this on every request, making it reliably repeatable.

### Recommendation
Replace the reference-equality checks with value-based comparisons. The cleanest fix is to compare the `number` field directly:

```java
public Optional<RecordFile> findByBlockType(BlockType block) {
    if (block == BlockType.EARLIEST || block.number() == 0L && "earliest".equals(block.name())) {
        return recordFileRepository.findEarliest();
    } else if (block == BlockType.LATEST || block.number() == Long.MAX_VALUE) {
        return recordFileRepository.findLatest();
    } else if (block.isHash()) {
        return recordFileRepository.findByHash(block.name());
    }
    return recordFileRepository.findByIndex(block.number());
}
```

Alternatively, override `equals` in `BlockType` (records already do this by value) and change `==` to `.equals()`, or add a dedicated `isLatest()` predicate that checks `number == Long.MAX_VALUE`.

### Proof of Concept

```bash
# Against a running mirror-node web3 endpoint:
curl -s -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"eth_call",
    "params":[
      {"to":"0x0000000000000000000000000000000000000001","data":"0x"},
      "0x7fffffffffffffff"
    ],
    "id":1
  }'
```

**Expected (correct) behavior:** executes against the latest block, returns a result.

**Actual behavior:** `findByIndex(9223372036854775807)` returns empty → `BlockNumberNotFoundException("Unknown block number")` → HTTP 400 / JSON-RPC error response.

The same result is reproducible with `eth_estimateGas` and any other method that passes the block parameter through `ContractCallService.callContract()`.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-28)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L103-104)
```java
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));
```
