All technical claims in the report have been verified against the actual codebase. Here is the assessment:

**Verification summary:**

- `OpcodeServiceImpl.getValue()` at lines 211–219 confirmed: `new BigInteger(ethereumTransaction.getValue())` with no empty-array guard. [1](#0-0) 
- Called from `buildCallServiceParameters()` at line 173 confirmed. [2](#0-1) 
- `GenericControllerAdvice` catches `IllegalArgumentException` → HTTP 400 confirmed. [3](#0-2) 
- `handleExceptionInternal` leaks `ex.getMessage()` for 4xx responses confirmed. [4](#0-3) 
- `ConvertEthereumTransactionValueMigration` SQL explicitly filters `length(value) > 0`, proving zero-length rows exist in the DB. [5](#0-4) 
- `updateTransactionEmptyWeiBars` test sets `value = new byte[]{}` and asserts it is stored as-is. [6](#0-5) 

---

## Audit Report

## Title
`NumberFormatException` on Zero-Length `value` Byte Array Crashes Opcode Replay in `OpcodeServiceImpl.getValue()`

## Summary
`OpcodeServiceImpl.getValue()` calls `new BigInteger(ethereumTransaction.getValue())` without guarding against a zero-length byte array. Java's `BigInteger(byte[])` constructor requires at least one byte and throws `NumberFormatException` (a subclass of `IllegalArgumentException`) on an empty array. Zero-length `value` byte arrays are a documented, persisted state in the `ethereum_transaction` table. Any caller supplying the hash of such a transaction to the opcode replay endpoint will receive HTTP 400 with an internal error string instead of the expected trace.

## Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java`, lines 211–219:

```java
private BigInteger getValue(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
    if (ethereumTransaction != null) {
        return new BigInteger(ethereumTransaction.getValue()); // throws on byte[0]
    }
    ...
}
``` [1](#0-0) 

This is called unconditionally at line 173:
```java
.value(getValue(ethTransaction, contractResult).longValue())
``` [2](#0-1) 

**Root cause:** The code assumes `EthereumTransaction.value` always contains at least one byte. This assumption is false. Zero-length values are explicitly acknowledged by:

1. `ConvertEthereumTransactionValueMigration`'s SELECT query, which filters `length(value) > 0`, proving zero-length rows are present in the DB and were intentionally skipped by the migration. [5](#0-4) 

2. `EthereumTransactionHandlerTest.updateTransactionEmptyWeiBars`, which sets `value = new byte[]{}` and asserts it is persisted as-is. [6](#0-5) 

**Why exception handling is insufficient:** `NumberFormatException` extends `IllegalArgumentException`. `GenericControllerAdvice` catches `IllegalArgumentException` and routes it to `handleExceptionInternal` with `BAD_REQUEST`: [3](#0-2) 

`handleExceptionInternal` includes `ex.getMessage()` in the response body for all non-5xx status codes: [7](#0-6) 

This means the raw internal error string `"Zero length BigInteger"` is returned to the caller.

## Impact Explanation
Any historical Ethereum transaction whose `value` column was stored as a zero-length byte array permanently cannot be replayed through `/api/v1/contracts/results/{hash}/opcodes`. The endpoint returns HTTP 400 with the internal error string `"Zero length BigInteger"` instead of the expected opcode trace. This is a targeted, repeatable denial-of-opcode-trace for specific transactions, with no funds at direct risk but with concrete loss of auditability and debuggability for those executions. The HTTP 400 response is also misleading — it implies bad user input when the transaction hash is perfectly valid.

## Likelihood Explanation
The precondition (a zero-length `value` in the DB) is explicitly acknowledged by the codebase itself (migration SQL, test fixture). An unprivileged caller needs only the Ethereum transaction hash of any such transaction — all transaction hashes are public on-chain data. No authentication, no special role, and no rate-limit bypass is required. The trigger is deterministic and repeatable.

## Recommendation
Add an empty-array guard in `getValue()` before constructing the `BigInteger`:

```java
private BigInteger getValue(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
    if (ethereumTransaction != null) {
        byte[] val = ethereumTransaction.getValue();
        if (ArrayUtils.isEmpty(val)) {
            return ZERO;
        }
        return new BigInteger(val);
    }
    if (contractResult.getAmount() != null) {
        return BigInteger.valueOf(contractResult.getAmount());
    }
    return ZERO;
}
```

`ArrayUtils` is already imported in this class. [8](#0-7) 

## Proof of Concept
1. Identify any Ethereum transaction in the `ethereum_transaction` table where `value` is a zero-length byte array (i.e., `value IS NOT NULL AND length(value) = 0`). These rows are confirmed to exist and are skipped by `ConvertEthereumTransactionValueMigration`.
2. Obtain the transaction hash (public on-chain data).
3. Send a GET request to `/api/v1/contracts/results/{hash}/opcodes`.
4. Observe HTTP 400 response with body containing `"Zero length BigInteger"` instead of the expected opcode trace.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L17-17)
```java
import org.apache.commons.lang3.ArrayUtils;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L173-173)
```java
                .value(getValue(ethTransaction, contractResult).longValue())
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L211-219)
```java
    private BigInteger getValue(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
        if (ethereumTransaction != null) {
            return new BigInteger(ethereumTransaction.getValue());
        }
        if (contractResult.getAmount() != null) {
            return BigInteger.valueOf(contractResult.getAmount());
        }
        return ZERO;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L89-93)
```java
    @ExceptionHandler({HttpMessageConversionException.class, IllegalArgumentException.class, InvalidInputException.class
    })
    private ResponseEntity<?> badRequest(final Exception e, final WebRequest request) {
        return handleExceptionInternal(e, null, null, BAD_REQUEST, request);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L165-167)
```java
        var message = statusCode instanceof HttpStatus hs ? hs.getReasonPhrase() : statusCode.toString();
        var detail = !statusCode.is5xxServerError() ? ex.getMessage() : StringUtils.EMPTY; // Don't leak server errors
        var genericErrorResponse = new GenericErrorResponse(message, detail, StringUtils.EMPTY);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/ConvertEthereumTransactionValueMigration.java (L19-22)
```java
    private static final String SELECT_NON_NULL_VALUE_SQL =
            "select consensus_timestamp, value " + "from ethereum_transaction "
                    + "where value is not null and length(value) > 0 "
                    + "order by consensus_timestamp";
```

**File:** importer/src/test/java/org/hiero/mirror/importer/parser/record/transactionhandler/EthereumTransactionHandlerTest.java (L375-403)
```java
    void updateTransactionEmptyWeiBars() {
        boolean create = true;
        var emptyBytes = new byte[] {};
        var ethereumTransaction = domainBuilder.ethereumTransaction(create).get();
        ethereumTransaction.setGasLimit(null);
        ethereumTransaction.setGasPrice(emptyBytes);
        ethereumTransaction.setMaxFeePerGas(emptyBytes);
        ethereumTransaction.setMaxPriorityFeePerGas(emptyBytes);
        ethereumTransaction.setValue(emptyBytes);
        doReturn(ethereumTransaction).when(ethereumTransactionParser).decode(any());

        var recordItem = recordItemBuilder.ethereumTransaction(create).build();
        var transaction = domainBuilder
                .transaction()
                .customize(t -> t.consensusTimestamp(recordItem.getConsensusTimestamp()))
                .get();

        transactionHandler.updateTransaction(transaction, recordItem);

        verify(entityListener).onEthereumTransaction(ethereumTransaction);
        assertThat(ethereumTransaction)
                .returns(null, EthereumTransaction::getGasLimit)
                .returns(emptyBytes, EthereumTransaction::getGasPrice)
                .returns(emptyBytes, EthereumTransaction::getMaxFeePerGas)
                .returns(emptyBytes, EthereumTransaction::getMaxPriorityFeePerGas)
                .returns(emptyBytes, EthereumTransaction::getValue);
        assertThat(recordItem.getEntityTransactions())
                .containsExactlyInAnyOrderEntriesOf(getExpectedEntityTransactions(recordItem, transaction));
    }
```
