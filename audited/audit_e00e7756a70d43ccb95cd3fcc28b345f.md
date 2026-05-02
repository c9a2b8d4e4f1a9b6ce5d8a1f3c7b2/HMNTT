### Title
Historical Contract Lookup Uses Current State Instead of Historical Timestamp in `buildOpcodesResponse()`

### Summary
In `OpcodeServiceImpl.buildOpcodesResponse()`, the recipient entity is resolved by calling `commonEntityAccessor.get(recipientAddress, Optional.empty())` with `Optional.empty()` as the timestamp, which queries the **current** (live) state of the entity rather than its state at the historical consensus timestamp of the replayed transaction. If the contract was deleted after the historical transaction, the lookup returns empty and the response reports `contractId = null` and `address = 0x0000...0000`. If the contract was deleted and a new contract was created at the same EVM address, the lookup returns the wrong entity, reporting a completely different `contractId` and `address` than what was recorded in Hashgraph history.

### Finding Description

**Exact code location:** `web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java`, `buildOpcodesResponse()`, lines 120–150, specifically line 125.

```java
// OpcodeServiceImpl.java, lines 120-133
private OpcodesResponse buildOpcodesResponse(@NonNull OpcodesProcessingResult result) {
    final var recipientAddress = result.recipient();
    Entity recipientEntity = null;
    if (recipientAddress != null && !recipientAddress.equals(EMPTY_ADDRESS)) {
        recipientEntity =
                commonEntityAccessor.get(recipientAddress, Optional.empty()).orElse(null); // <-- BUG
    }

    var address = EMPTY_ADDRESS.toHexString();
    String contractId = null;
    if (recipientEntity != null) {
        address = getEntityAddress(recipientEntity).toHexString();
        contractId = recipientEntity.toEntityId().toString();
    }
```

**Root cause:** `Optional.empty()` is passed as the timestamp, which causes `CommonEntityAccessor.get()` to branch into the "current state" path:

- For long-zero addresses: `entityRepository.findByIdAndDeletedIsFalse(entityId)` — returns nothing if deleted.
- For EVM addresses: `entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes)` — returns nothing if deleted, or returns a *different* entity if a new contract was deployed at the same EVM address.

The consensus timestamp of the replayed transaction is computed in `buildCallServiceParameters()` (line 169: `consensusTimestamp`) but is never threaded through to `buildOpcodesResponse()`.

**Exploit flow:**
1. Contract X (EVM address `0xABCD...`) is involved in a historical transaction at consensus timestamp T.
2. After T, Contract X is deleted (by its owner — no attacker privilege required).
3. Optionally, a new Contract Y is deployed at the same EVM address `0xABCD...`.
4. Attacker (unprivileged) calls `GET /api/v1/contracts/results/{txHash}/opcodes`.
5. `buildOpcodesResponse()` calls `commonEntityAccessor.get(0xABCD..., Optional.empty())`.
   - Scenario A (deleted, not replaced): returns `Optional.empty()` → `recipientEntity = null` → response: `contractId = null`, `address = 0x0000...0000`.
   - Scenario B (replaced by Contract Y): returns Contract Y's entity → response: `contractId = <Y's ID>`, `address = <Y's address>`.
6. Both scenarios produce a response that contradicts what Hashgraph recorded for that transaction.

**Why existing checks are insufficient:** The only guard is `if (recipientAddress != null && !recipientAddress.equals(EMPTY_ADDRESS))` (line 123), which only prevents processing a null/zero address. It does not protect against the entity lookup returning empty or a wrong entity due to post-transaction state changes.

The same pattern also appears in `getSenderAddress()` (line 178) and `getReceiverAddress()` (line 191), both using `Optional.empty()`.

### Impact Explanation
The `OpcodesResponse` fields `contractId` and `address` are the primary identifiers that consumers use to understand which contract was involved in a historical transaction. Returning `null`/zero-address or a completely different contract's identity for a historical replay directly misrepresents immutable Hashgraph history. Auditors, block explorers, forensic tools, and compliance systems relying on this endpoint receive falsified attribution data. In Scenario B (address reuse), the response actively attributes the historical execution to a different, potentially attacker-controlled contract.

### Likelihood Explanation
No privileged access is required by the attacker. The only precondition is the existence of a deleted contract that was involved in at least one historical transaction — a routine occurrence on any live network. The attacker only needs to submit a standard unauthenticated GET request. The condition is permanent once the contract is deleted, making it repeatable indefinitely.

### Recommendation
Pass the `consensusTimestamp` of the replayed transaction into `buildOpcodesResponse()` and replace `Optional.empty()` with `Optional.of(consensusTimestamp)`:

```java
// Fix: use historical timestamp
recipientEntity = commonEntityAccessor.get(recipientAddress, Optional.of(consensusTimestamp)).orElse(null);
```

Apply the same fix to `getSenderAddress()` and `getReceiverAddress()` which have the identical issue. The `consensusTimestamp` is already available in `processOpcodeCall()` via `params.getConsensusTimestamp()` and can be passed through to `buildOpcodesResponse()`.

### Proof of Concept
1. Deploy Contract X on a Hedera testnet; record its EVM address and a transaction hash involving it.
2. Delete Contract X (using its admin key).
3. Call `GET /api/v1/contracts/results/{txHash}/opcodes` with `Accept-Encoding: gzip`.
4. Observe the response: `"contractId": null, "address": "0x0000000000000000000000000000000000000000"`.
5. Compare against the on-chain record for the same transaction hash, which shows the original contract's ID and address — confirming the discrepancy. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L177-179)
```java
    private Address getSenderAddress(ContractResult contractResult) {
        final var address = commonEntityAccessor.evmAddressFromId(contractResult.getSenderId(), Optional.empty());
        return address != null ? address : EMPTY_ADDRESS;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L189-195)
```java
            if (ConversionUtils.isLongZero(address)) {
                final var entity =
                        commonEntityAccessor.get(address, Optional.empty()).orElse(null);
                if (entity != null) {
                    return getEntityAddress(entity);
                }
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L73-78)
```java
    private Optional<Entity> getEntityByMirrorAddressAndTimestamp(Address address, final Optional<Long> timestamp) {
        final var entityId = entityIdNumFromEvmAddress(address);
        return timestamp
                .map(t -> entityRepository.findActiveByIdAndTimestamp(entityId, t))
                .orElseGet(() -> entityRepository.findByIdAndDeletedIsFalse(entityId));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L80-84)
```java
    private Optional<Entity> getEntityByEvmAddressTimestamp(byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```
