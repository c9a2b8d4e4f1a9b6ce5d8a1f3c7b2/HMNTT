### Title
Missing Null-Byte Sanitization on `ContractResult.errorMessage` Enables PostgreSQL Insertion Failure and Log Truncation

### Summary
The `errorMessage` field in `ContractResult` is stored directly from the protobuf `ContractFunctionResult.getErrorMessage()` without passing through `DomainUtils.sanitize()`, unlike every other user-influenced string field in the codebase (`memo`, `name`, `symbol`). PostgreSQL explicitly rejects null bytes (0x0000) in text columns, and the codebase's own `DomainUtils.sanitize()` documents this constraint. An unprivileged user who deploys a contract that reverts with assembly-crafted data containing null bytes can trigger an importer insertion failure, causing the contract result record to be dropped from the mirror node database.

### Finding Description

**Exact code path:**

`ContractResult.java` line 49 declares `errorMessage` as a plain `String` with no custom setter: [1](#0-0) 

Three separate ingestion paths assign the raw protobuf value with no sanitization:

- `ContractResultServiceImpl.java` line 251: [2](#0-1) 

- `ContractResultMigration.java` line 98: [3](#0-2) 

- `AbstractBlockTransactionTransformer.java` line 148: [4](#0-3) 

**Root cause — failed assumption:** The codebase explicitly knows PostgreSQL rejects null bytes. `DomainUtils.sanitize()` was created for exactly this reason: [5](#0-4) 

It is applied to every other user-influenced string field — `memo`, `name`, `symbol`: [6](#0-5) [7](#0-6) 

`errorMessage` is the only user-controlled string field that is omitted.

**Exploit flow:** A Solidity contract uses inline assembly (`revert(ptr, size)`) to return revert data that embeds a null byte (0x00) inside the ABI-encoded error string. The Hedera consensus node records this in the `ContractFunctionResult.error_message` protobuf field. The mirror node importer reads it via `functionResult.getErrorMessage()` and calls `contractResult.setErrorMessage(...)` with no sanitization. When Hibernate/JDBC attempts to INSERT the row, PostgreSQL throws `ERROR: invalid byte sequence for encoding "UTF8": 0x00`, causing the entire contract result record to be lost.

### Impact Explanation

The immediate impact is **silent data loss**: the `contract_result` row for the affected transaction is never written to the mirror node database. Any downstream consumer (REST API, analytics, block explorers) querying that transaction's result will find no record. Because the importer typically logs the error and continues, the loss is not immediately visible. Secondary impact: if the raw `errorMessage` value reaches a C-based logging sink before the PostgreSQL error, the null byte terminates the C string, hiding everything after it — exactly the masking described in the question. Severity is medium: it does not compromise funds or consensus, but it allows any paying user to selectively erase their own (or others') contract result records from the mirror node.

### Likelihood Explanation

Any Hedera account holder can deploy a contract and call it — no special role or privilege is required beyond paying the transaction fee. The attack is trivially repeatable: one assembly `revert` instruction is sufficient. The attacker does not need access to the mirror node infrastructure. The only uncertainty is whether the Hedera network passes the raw null byte through to the protobuf `error_message` field or hex-encodes it first; if hex-encoded, the null byte becomes the two ASCII characters `00` and is harmless. However, the codebase's own `BytesDecoder` handles both hex-prefixed and plain-string `errorMessage` values, confirming that plain (non-hex) strings do reach this field in practice. [8](#0-7) 

### Recommendation

Add a custom setter on `ContractResult` mirroring the pattern used for `AbstractToken.name`/`symbol`:

```java
public void setErrorMessage(String errorMessage) {
    this.errorMessage = DomainUtils.sanitize(errorMessage);
}
```

This is consistent with the existing pattern and requires no schema changes. Apply the same fix to the `MigrationContractResult` POJO used in `ContractResultMigration`.

### Proof of Concept

1. Deploy the following Solidity contract on a Hedera testnet:
```solidity
contract NullByteRevert {
    function trigger() external pure {
        assembly {
            // ABI-encode Error("ok\x00hidden") with a null byte at offset 35
            let ptr := mload(0x40)
            mstore(ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
            mstore(add(ptr, 4),  0x0000000000000000000000000000000000000000000000000000000000000020)
            mstore(add(ptr, 36), 0x000000000000000000000000000000000000000000000000000000000000000a)
            // "ok\x00hidden" = 6f 6b 00 68 69 64 64 65 6e 00
            mstore(add(ptr, 68), 0x6f6b0068696464656e000000000000000000000000000000000000000000000000)
            revert(ptr, 100)
        }
    }
}
```
2. Call `trigger()` from any account.
3. Query the mirror node REST API for the transaction's contract result: `GET /api/v1/contracts/results/{transactionId}`.
4. Observe either: (a) HTTP 404 — the row was never inserted due to PostgreSQL rejection, or (b) the `error_message` field is truncated at the null byte, showing only `"ok"` instead of `"ok\x00hidden"`.
5. Check the importer logs for `PSQLException: ERROR: invalid byte sequence` to confirm the insertion failure.

### Citations

**File:** common/src/main/java/org/hiero/mirror/common/domain/contract/ContractResult.java (L49-49)
```java
    private String errorMessage;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L251-251)
```java
            contractResult.setErrorMessage(functionResult.getErrorMessage());
```

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/ContractResultMigration.java (L98-99)
```java
            contractResult.setErrorMessage(contractFunctionResult.getErrorMessage());
            update(contractResult);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/downloader/block/transformer/AbstractBlockTransactionTransformer.java (L146-149)
```java
        contractResultbuilder
                .setContractCallResult(evmTransactionResult.getResultData())
                .setErrorMessage(evmTransactionResult.getErrorMessage())
                .setGasUsed(evmTransactionResult.getGasUsed());
```

**File:** common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java (L232-241)
```java
    /**
     * Cleans a string of invalid characters that would cause it to fail when inserted into the database. In particular,
     * PostgreSQL does not allow the null character (0x0000) to be inserted.
     *
     * @param input string containing potentially invalid characters
     * @return the cleaned string
     */
    public static String sanitize(String input) {
        return StringUtils.isNotEmpty(input) ? input.replace(NULL_CHARACTER, NULL_REPLACEMENT) : input;
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/AbstractEntity.java (L196-199)
```java
        public B memo(String memo) {
            this.memo = DomainUtils.sanitize(memo);
            return self();
        }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/token/AbstractToken.java (L109-115)
```java
    public void setName(String name) {
        this.name = DomainUtils.sanitize(name);
    }

    public void setSymbol(String symbol) {
        this.symbol = DomainUtils.sanitize(symbol);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/convert/BytesDecoder.java (L24-44)
```java
    public static String maybeDecodeSolidityErrorStringToReadableMessage(final String revertReason) {
        final var isNullOrEmpty = revertReason == null || revertReason.isEmpty();

        if (isNullOrEmpty || revertReason.length() <= ERROR_FUNCTION_SELECTOR.length()) {
            return StringUtils.EMPTY;
        }

        if (isAbiEncodedErrorString(revertReason)) {
            final var encodedMessageHex = revertReason.substring(ERROR_FUNCTION_SELECTOR.length());
            try {
                final var encodedMessage = Hex.decode(encodedMessageHex);
                final var tuple = STRING_DECODER.decode(encodedMessage);
                if (!tuple.isEmpty()) {
                    return tuple.get(0);
                }
            } catch (Exception e) {
                return StringUtils.EMPTY;
            }
        }
        return StringUtils.EMPTY;
    }
```
