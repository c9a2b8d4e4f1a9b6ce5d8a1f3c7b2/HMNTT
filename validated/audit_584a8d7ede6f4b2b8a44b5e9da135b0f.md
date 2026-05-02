I have verified all code references against the actual source. Here is my assessment:

**All technical claims check out:**

- `getSenderAddress()` at line 178 uses `Optional.empty()` — confirmed. [1](#0-0) 
- `getReceiverAddress()` at lines 191 and 203 uses `Optional.empty()` — confirmed. [2](#0-1) 
- `consensusTimestamp` is a local variable in `buildCallServiceParameters()` and is set on the `ContractDebugParameters` object but is never forwarded to either address-resolution helper — confirmed. [3](#0-2) 
- `CommonEntityAccessor.evmAddressFromId()` with `Optional.empty()` calls `findByIdAndDeletedIsFalse()` (current state) and applies the `evmAddress > alias > entityId` priority — confirmed. [4](#0-3) 
- `ContractDebugService.processOpcodeCall()` correctly sets the EVM state timestamp to `consensusTimestamp - 1`, meaning the EVM storage/balance state IS historical — but the `sender` and `receiver` addresses fed into it are resolved from current DB state. [5](#0-4) 

The precondition is realistic: a Hedera account created with an ED25519 key has no alias and no `evmAddress`, so its original `msg.sender` is the long-zero address `toAddress(entityId)`. If `CryptoUpdate` later adds an ECDSA key (setting alias/evmAddress), the replay will use the new EVM address as sender, diverging from the original execution. This is a normal Hedera lifecycle event.

---

## Audit Report

## Title
Stale Entity State in `OpcodeServiceImpl` Address Resolution Causes Divergent Historical Replay

## Summary
`OpcodeServiceImpl.getSenderAddress()` and `getReceiverAddress()` resolve entity addresses using **current** database state (`Optional.empty()`) rather than the entity state at the original transaction's `consensusTimestamp`. Because `getEntityAddress()` / `evmAddressFromId()` apply the priority `evmAddress > alias > entityId`, any entity whose address representation changed after the original transaction will produce a different `msg.sender` or receiver in the replay, yielding an opcode trace that diverges from the real historical execution.

## Finding Description

**Exact code path:**

`OpcodeServiceImpl.getSenderAddress()` passes `Optional.empty()` to `CommonEntityAccessor.evmAddressFromId()`:

```java
// OpcodeServiceImpl.java line 178
final var address = commonEntityAccessor.evmAddressFromId(
    contractResult.getSenderId(), Optional.empty());  // ← no timestamp
``` [1](#0-0) 

`CommonEntityAccessor.evmAddressFromId()` with `Optional.empty()` calls `findByIdAndDeletedIsFalse()` (current state) and then applies:

```java
// CommonEntityAccessor.java lines 98–106
if (entity.getEvmAddress() != null) {
    return Address.wrap(...entity.getEvmAddress()...);   // priority 1
}
if (entity.getAlias() != null && entity.getAlias().length == EVM_ADDRESS_LENGTH) {
    return Address.wrap(...entity.getAlias()...);        // priority 2
}
return toAddress(entityId);                             // priority 3
``` [4](#0-3) 

`getReceiverAddress()` has the same flaw for long-zero addresses and for non-Ethereum transactions: [2](#0-1) 

**Root cause / failed assumption:** The code assumes an entity's `evmAddress` and `alias` are immutable after creation. In practice, a Hedera account created with an ED25519 key has neither field set; its EVM identity is the long-zero address `toAddress(entityId)`. A subsequent `CryptoUpdate` adding an ECDSA key sets the alias (and/or `evmAddress`) to a new 20-byte value. The `consensusTimestamp` is already present in `buildCallServiceParameters()` and is correctly forwarded to `ContractDebugParameters` for EVM state replay, but is never passed to the address-resolution helpers. [3](#0-2) 

## Impact Explanation
The opcodes endpoint is the authoritative debugging and audit surface for historical EVM execution. A divergent replay can:

- Show a transaction as **failed** when it originally **succeeded** (or vice versa) — e.g., if the contract has `require(msg.sender == owner)` and the stored `owner` matches the original long-zero address but the replay uses the new ECDSA address.
- Produce a completely different opcode sequence and storage-change trace, making forensic analysis of exploits unreliable.
- Be triggered deterministically and repeatably by any unauthenticated caller once the precondition exists on-chain.

## Likelihood Explanation
- No authentication or privilege is required; the endpoint is public.
- The precondition (entity gaining an `evmAddress`/alias after a historical contract call) is a normal Hedera lifecycle event: any account created with an ED25519 key that later has an ECDSA key added via `CryptoUpdate` satisfies it.
- The attacker needs only a valid transaction ID or hash, which is public on-chain data.
- The divergence is permanent and reproducible on every subsequent call once the precondition exists.

## Recommendation
Pass `Optional.of(consensusTimestamp)` to all address-resolution calls inside `getSenderAddress()` and `getReceiverAddress()`. Concretely:

1. Add `consensusTimestamp` as a parameter to `getSenderAddress(ContractResult, long)` and `getReceiverAddress(EthereumTransaction, ContractResult, int, long)`.
2. Replace every `Optional.empty()` in those two methods with `Optional.of(consensusTimestamp)`.
3. Apply the same fix to the `buildOpcodesResponse()` helper which also calls `commonEntityAccessor.get(recipientAddress, Optional.empty())`. [6](#0-5) 

## Proof of Concept

1. Create account `A` (e.g., `0.0.5000`) with an ED25519 key. At this point `evmAddress = null`, `alias = null`; its EVM identity is `toAddress(0.0.5000) = 0x0000…1388`.
2. Deploy a contract that stores `owner = msg.sender` in its constructor and exposes `require(msg.sender == owner)` in a function. Call that function from account `A` — transaction `T1` succeeds; `msg.sender = 0x0000…1388`.
3. Later, submit a `CryptoUpdate` for account `A` adding an ECDSA key, which sets `alias = evmAddress = 0xAAAA…` in the DB.
4. Call `GET /api/v1/contracts/results/T1/opcodes` (no authentication needed).
5. `getSenderAddress()` fetches the **current** entity state, finds `evmAddress = 0xAAAA…`, and sets `sender = 0xAAAA…` in `ContractDebugParameters`.
6. The replay EVM sees `msg.sender = 0xAAAA…`. The `require(msg.sender == owner)` check fails (owner is `0x0000…1388`). The opcode trace shows a **REVERT** — the original transaction **succeeded**.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L120-133)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L165-175)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L189-204)
```java
            if (ConversionUtils.isLongZero(address)) {
                final var entity =
                        commonEntityAccessor.get(address, Optional.empty()).orElse(null);
                if (entity != null) {
                    return getEntityAddress(entity);
                }
            }
            return address;
        }

        if (transactionType == CONTRACTCREATEINSTANCE.getProtoId()) {
            return EMPTY_ADDRESS;
        }
        final var contractId = EntityId.of(contractResult.getContractId());
        final var address = commonEntityAccessor.evmAddressFromId(contractId, Optional.empty());
        return address != null ? address : EMPTY_ADDRESS;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L86-107)
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

        if (entity.getEvmAddress() != null) {
            return Address.wrap(org.apache.tuweni.bytes.Bytes.wrap(entity.getEvmAddress()));
        }

        if (entity.getAlias() != null && entity.getAlias().length == EVM_ADDRESS_LENGTH) {
            return Address.wrap(org.apache.tuweni.bytes.Bytes.wrap(entity.getAlias()));
        }

        return toAddress(entityId);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractDebugService.java (L51-52)
```java
        ctx.setTimestamp(Optional.of(params.getConsensusTimestamp() - 1));
        ctx.setOpcodeContext(opcodeContext);
```
