All four required checks pass against the actual code. Every line reference, code path, and behavioral claim is verified.

---

Audit Report

## Title
Deleted Sender Entity Causes Silent Treasury Substitution in Opcode Replay, Producing Incorrect `msg.sender` Trace

## Summary
`OpcodeServiceImpl.getSenderAddress()` resolves the sender using the **current** entity state (`Optional.empty()`) rather than the historical state at `consensusTimestamp`. When the original sender has since been deleted, `evmAddressFromId` returns `Address.ZERO`. The downstream guard in `TransactionExecutionService.getSenderAccountID()` silently substitutes the treasury account as the EVM sender, causing the opcode replay to execute with the wrong `msg.sender` and producing a structurally misleading trace that any unprivileged caller can trigger.

## Finding Description

**Verified code path:**

`OpcodeServiceImpl.buildCallServiceParameters()` (line 172) calls `getSenderAddress(contractResult)`:

```java
// OpcodeServiceImpl.java lines 177–180
private Address getSenderAddress(ContractResult contractResult) {
    final var address = commonEntityAccessor.evmAddressFromId(
            contractResult.getSenderId(), Optional.empty());  // ← always current state
    return address != null ? address : EMPTY_ADDRESS;
}
``` [1](#0-0) 

`evmAddressFromId` with `Optional.empty()` takes the `orElseGet` branch, calling `findByIdAndDeletedIsFalse`. If the entity is deleted (returns empty), `entity == null` and `Address.ZERO` is returned:

```java
// CommonEntityAccessor.java lines 87–95
Entity entity = timestamp
        .map(t -> entityRepository
                .findActiveByIdAndTimestamp(entityId.getId(), t)
                .orElse(null))
        .orElseGet(() -> entityRepository
                .findByIdAndDeletedIsFalse(entityId.getId())
                .orElse(null));
if (entity == null) {
    return Address.ZERO;
}
``` [2](#0-1) 

`Address.ZERO` is stored as `sender` in `ContractDebugParameters` at line 172: [3](#0-2) 

In `TransactionExecutionService.getSenderAccountID()`, the zero-address + zero-value guard silently substitutes the treasury:

```java
// TransactionExecutionService.java lines 241–242
if (params.getSender().isZero() && params.getValue() == 0L) {
    return EntityIdUtils.toAccountId(systemEntity.treasuryAccount());
}
``` [4](#0-3) 

**Root cause:** `getSenderAddress` ignores the `consensusTimestamp` that is available in the same `buildCallServiceParameters` scope (line 169 uses it for `block`, line 154 fetches `contractResult` by it). Passing `Optional.of(consensusTimestamp)` would route `evmAddressFromId` to `findActiveByIdAndTimestamp`, which correctly resolves the sender as it existed at transaction time. [5](#0-4) 

**Failed assumption:** The code assumes any entity referenced by a stored `ContractResult.senderId` will remain non-deleted indefinitely. Hedera accounts can be deleted after a transaction is finalized via `CryptoDelete`.

## Impact Explanation
The opcode trace returned to the caller contains `CALLER` opcodes reflecting the treasury address, not the original sender. Any contract logic gated on `msg.sender` (access control checks, ownership assertions, allowance logic) is replayed against the wrong identity, producing a trace that does not match what actually executed on-chain. Security auditors or automated tools consuming this endpoint to verify historical contract behavior receive structurally incorrect data. The `failed` field in the response may also diverge from the original outcome if the contract's execution path branches on `msg.sender`. [6](#0-5) 

## Likelihood Explanation
The precondition — a historical contract transaction whose sender account was subsequently deleted — is a normal Hedera lifecycle event. No special privilege is required: the opcode endpoint has no authentication guard, only a gzip header check and a rate limiter. Any public caller who knows a transaction ID or hash meeting the precondition can trigger the incorrect replay repeatedly. [7](#0-6) 

## Recommendation
Pass the `consensusTimestamp` to `getSenderAddress` and forward it to `evmAddressFromId`:

```java
// OpcodeServiceImpl.java — fix
private Address getSenderAddress(ContractResult contractResult, long consensusTimestamp) {
    final var address = commonEntityAccessor.evmAddressFromId(
            contractResult.getSenderId(), Optional.of(consensusTimestamp)); // ← historical lookup
    return address != null ? address : EMPTY_ADDRESS;
}
```

Update the call site at line 172 accordingly:

```java
.sender(getSenderAddress(contractResult, consensusTimestamp))
```

This routes `evmAddressFromId` to `findActiveByIdAndTimestamp`, which resolves the entity as it existed at the time of the original transaction, matching the behavior already used for block resolution on line 158. [8](#0-7) 

## Proof of Concept

1. Submit a contract call transaction `T` at time `t0` from account `A` (e.g., a contract that emits `msg.sender` in its logic).
2. After `t0`, delete account `A` via `CryptoDelete`.
3. Call the opcode trace endpoint with the transaction ID or hash of `T`.
4. `getSenderAddress` calls `evmAddressFromId(A.id, Optional.empty())` → `findByIdAndDeletedIsFalse(A.id)` returns empty → `Address.ZERO` is returned.
5. `getSenderAccountID` sees `sender.isZero() && value == 0` → returns treasury account ID.
6. The EVM replay executes with treasury as `msg.sender`.
7. Observe that all `CALLER` opcodes in the returned trace reflect the treasury address, not `A`'s address, and that any `msg.sender`-gated branch in the contract may produce a different execution path than the original.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L63-74)
```java
    @Override
    public OpcodesResponse processOpcodeCall(@NonNull OpcodeRequest opcodeRequest) {
        return ContractCallContext.run(ctx -> {
            final var params = buildCallServiceParameters(opcodeRequest.getTransactionIdOrHashParameter());
            final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);

            ctx.setOpcodeContext(opcodeContext);

            final OpcodesProcessingResult result = contractDebugService.processOpcodeCall(params, opcodeContext);
            return buildOpcodesResponse(result);
        });
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L120-149)
```java
    private OpcodesResponse buildOpcodesResponse(@NonNull OpcodesProcessingResult result) {
        final var recipientAddress = result.recipient();
        Entity recipientEntity = null;
        if (recipientAddress != null && !recipientAddress.equals(EMPTY_ADDRESS)) {
            recipientEntity =
                    commonEntityAccessor.get(recipientAddress, Optional.empty()).orElse(null);
        }

        var address = EMPTY_ADDRESS.toHexString();
        String contractId = null;
        if (recipientEntity != null) {
            address = getEntityAddress(recipientEntity).toHexString();
            contractId = recipientEntity.toEntityId().toString();
        }

        final var txnResult = result.transactionProcessingResult();
        var returnValue = txnResult != null ? txnResult.contractCallResult() : HEX_PREFIX;
        if (returnValue == null || returnValue.isEmpty()) {
            returnValue = HEX_PREFIX;
        }

        final var opcodes = result.opcodes() != null ? result.opcodes() : new ArrayList<Opcode>();

        return new OpcodesResponse()
                .address(address)
                .contractId(contractId)
                .failed(txnResult == null || !txnResult.isSuccessful())
                .gas(txnResult != null ? txnResult.gasUsed() : 0L)
                .opcodes(opcodes)
                .returnValue(returnValue);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L152-175)
```java
    private ContractDebugParameters buildCallServiceParameters(
            Long consensusTimestamp, Transaction transaction, EthereumTransaction ethTransaction) {
        final var contractResult = contractResultRepository
                .findById(consensusTimestamp)
                .orElseThrow(() -> new EntityNotFoundException("Contract result not found: " + consensusTimestamp));

        final var blockType = recordFileService
                .findByTimestamp(consensusTimestamp)
                .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
                .orElse(BlockType.LATEST);

        final var transactionType = transaction != null ? transaction.getType() : TransactionType.UNKNOWN.getProtoId();

        return ContractDebugParameters.builder()
                .block(blockType)
                .callData(getCallDataBytes(ethTransaction, contractResult))
                .ethereumData(getEthereumDataBytes(ethTransaction))
                .consensusTimestamp(consensusTimestamp)
                .gas(getGasLimit(ethTransaction, contractResult))
                .receiver(getReceiverAddress(ethTransaction, contractResult, transactionType))
                .sender(getSenderAddress(contractResult))
                .value(getValue(ethTransaction, contractResult).longValue())
                .build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L177-180)
```java
    private Address getSenderAddress(ContractResult contractResult) {
        final var address = commonEntityAccessor.evmAddressFromId(contractResult.getSenderId(), Optional.empty());
        return address != null ? address : EMPTY_ADDRESS;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L86-96)
```java
    public Address evmAddressFromId(EntityId entityId, final Optional<Long> timestamp) {
        Entity entity = timestamp
                .map(t -> entityRepository
                        .findActiveByIdAndTimestamp(entityId.getId(), t)
                        .orElse(null))
                .orElseGet(() -> entityRepository
                        .findByIdAndDeletedIsFalse(entityId.getId())
                        .orElse(null));
        if (entity == null) {
            return Address.ZERO;
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L239-243)
```java
    private AccountID getSenderAccountID(final CallServiceParameters params) {
        // Set a default account to keep the sender parameter optional.
        if (params.getSender().isZero() && params.getValue() == 0L) {
            return EntityIdUtils.toAccountId(systemEntity.treasuryAccount());
        }
```
