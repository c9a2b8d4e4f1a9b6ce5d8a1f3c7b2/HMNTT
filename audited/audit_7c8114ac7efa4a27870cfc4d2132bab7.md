### Title
Reference-Equality Bypass on `BlockType.LATEST` via Hex-Encoded `Long.MAX_VALUE` Causes `BlockNumberNotFoundException`

### Summary
`BlockType.of("0x7fffffffffffffff")` creates a new `BlockType` instance with `number = Long.MAX_VALUE` instead of returning the `BlockType.LATEST` singleton. Because `RecordFileServiceImpl.findByBlockType()` guards the `findLatest()` path with a reference-equality check (`block == BlockType.LATEST`), the new instance bypasses it, falls through to `recordFileRepository.findByIndex(Long.MAX_VALUE)`, returns `Optional.empty()`, and causes `BlockNumberNotFoundException` on every smart contract call that uses this block parameter.

### Finding Description

**Root cause — `BlockType.java` lines 12 and 37–55:**

`BlockType.LATEST` is a singleton: `new BlockType("latest", Long.MAX_VALUE)`. [1](#0-0) 

`BlockType.of("0x7fffffffffffffff")` does not match any named case in the `switch`, so it calls `extractNumericBlock`. There, `Long.parseLong("7fffffffffffffff", 16)` succeeds and equals `Long.MAX_VALUE`, and the method returns `new BlockType("0x7fffffffffffffff", Long.MAX_VALUE)` — a brand-new heap object, not the singleton. [2](#0-1) 

**Failed guard — `RecordFileServiceImpl.java` lines 22–26:**

The guard uses `==` (reference equality). The newly created instance is never `==` to `BlockType.LATEST`, so the `findLatest()` branch is skipped and `findByIndex(Long.MAX_VALUE)` is called instead. [3](#0-2) 

`findByIndex(Long.MAX_VALUE)` queries `record_file where index = 9223372036854775807`, which will never match any real block, returning `Optional.empty()`. [4](#0-3) 

The caller in `ContractCallService` unwraps the empty `Optional` and throws `BlockNumberNotFoundException`, which the controller maps to HTTP 400. [5](#0-4) 

The same bypass applies to `BlockType.EARLIEST` (`number = 0L`) if a user passes `"0x0"` or `"0"`, though `EARLIEST` is less impactful since index 0 likely exists.

### Impact Explanation
Any unprivileged caller of the JSON-RPC `eth_call` / `eth_estimateGas` endpoints can force every smart contract call that targets the "latest" block (the default) to fail with a 400 error by supplying `"blockNumber": "0x7fffffffffffffff"`. This disrupts contract execution queries and can be used as a targeted denial-of-service against any dApp relying on the mirror node's web3 API. No funds are directly at risk, but smart contract state reads and simulations are completely broken for the affected block parameter.

### Likelihood Explanation
The attack requires zero privileges — only the ability to send an HTTP request to the public web3 endpoint. The hex value `0x7fffffffffffffff` is a well-known sentinel (`Long.MAX_VALUE`) that any developer or attacker familiar with Java or EVM tooling would try. It is trivially repeatable and requires no special knowledge of the internal codebase.

### Recommendation
In `BlockType.of()`, normalize the parsed number back to the singleton before returning:

```java
// in extractNumericBlock, before returning:
long blockNumber = Long.parseLong(cleanedValue, radix);
if (blockNumber == LATEST.number()) return LATEST;
if (blockNumber == EARLIEST.number()) return EARLIEST;
return new BlockType(value, blockNumber);
```

Alternatively, change the guard in `RecordFileServiceImpl.findByBlockType()` to compare by value rather than reference:

```java
if (block.number() == BlockType.LATEST.number()) {
    return recordFileRepository.findLatest();
}
```

The normalization approach in `BlockType.of()` is preferable because it fixes the invariant at the source and protects all future callers.

### Proof of Concept

```bash
# Assuming the web3 endpoint is at localhost:8545
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"eth_call",
    "params":[
      {"to":"0x<any_contract_address>","data":"0x<any_selector>"},
      "0x7fffffffffffffff"
    ],
    "id":1
  }'
# Expected (buggy) response: HTTP 400, "Unknown block number"
# Expected (correct) response: result from the latest block
```

Reproducible steps:
1. Start the mirror node web3 service with any populated database.
2. Send `eth_call` with block tag `"0x7fffffffffffffff"`.
3. `BlockType.of("0x7fffffffffffffff")` creates a new non-singleton instance.
4. `findByBlockType()` skips `findLatest()`, calls `findByIndex(Long.MAX_VALUE)`.
5. Repository returns `Optional.empty()`.
6. `BlockNumberNotFoundException` is thrown; caller receives HTTP 400.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L12-12)
```java
    public static final BlockType LATEST = new BlockType("latest", Long.MAX_VALUE);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L27-29)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
    @Query("select r from RecordFile r where r.index = ?1")
    Optional<RecordFile> findByIndex(long index);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/exception/BlockNumberNotFoundException.java (L1-11)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.exception;

public class BlockNumberNotFoundException extends InvalidInputException {

    public static final String UNKNOWN_BLOCK_NUMBER = "Unknown block number";

    public BlockNumberNotFoundException() {
        super(UNKNOWN_BLOCK_NUMBER);
    }
```
