Now I have all the evidence needed. Let me trace the exact code path to confirm the vulnerability.

The critical path is in `EntityIdServiceImpl.findByEvmAddress()`:

```java
// lines 169-178
private Optional<EntityId> findByEvmAddress(byte[] evmAddress, boolean throwRecoverableError) {
    var id = Optional.ofNullable(DomainUtils.fromEvmAddress(evmAddress))
            .or(() -> entityRepository.findByEvmAddress(evmAddress).map(EntityId::of));
    ...
    return id;
}
```

`DomainUtils.fromEvmAddress()` at line 289-291 short-circuits for long-zero addresses and returns an `EntityId` directly — `entityRepository.findByEvmAddress()` (with its `deleted <> true` guard) is **never called**.

The test `lookupContractEvmAddressSpecific` (line 240-246) confirms this: it resolves a long-zero address to an `EntityId` with **no entity persisted in the DB at all**, proving the DB guard is fully bypassed.

---

### Title
Long-Zero EVM Address Bypasses Deleted-Entity Guard in `EntityIdServiceImpl.findByEvmAddress()`

### Summary
`EntityIdServiceImpl.findByEvmAddress()` short-circuits to `DomainUtils.fromEvmAddress()` for any long-zero EVM address (first 12 bytes zero), returning an `EntityId` directly from the numeric value without any database lookup. This completely bypasses the `deleted <> true` guard in `EntityRepository.findByEvmAddress()`, allowing a crafted long-zero address to resolve to a deleted entity's ID.

### Finding Description
**Exact code path:**

`EntityIdServiceImpl.findByEvmAddress()` — `importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java`, lines 169–178:

```java
private Optional<EntityId> findByEvmAddress(byte[] evmAddress, boolean throwRecoverableError) {
    var id = Optional.ofNullable(DomainUtils.fromEvmAddress(evmAddress))
            .or(() -> entityRepository.findByEvmAddress(evmAddress).map(EntityId::of));
    ...
    return id;
}
```

`DomainUtils.fromEvmAddress()` — `common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java`, lines 285–297:

```java
public static EntityId fromEvmAddress(byte[] evmAddress) {
    try {
        if (isLongZeroAddress(evmAddress)) {
            final var num = Longs.fromByteArray(Arrays.copyOfRange(evmAddress, 12, 20));
            return EntityId.of(commonProperties.getShard(), commonProperties.getRealm(), num);
        }
    } catch (InvalidEntityException ex) { ... }
    return null;
}
```

`EntityRepository.findByEvmAddress()` — `importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java`, line 19–20:

```java
@Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**Root cause:** The `Optional.ofNullable(...).or(...)` chain means `entityRepository.findByEvmAddress()` is only called when `DomainUtils.fromEvmAddress()` returns `null`. For any long-zero address, `fromEvmAddress()` returns a non-null `EntityId` constructed purely from the numeric suffix — no DB query, no deletion check. The `deleted <> true` guard in the repository is structurally unreachable for this input class.

**Failed assumption:** The code assumes that `DomainUtils.fromEvmAddress()` returning a non-null result implies the entity is valid and active. It does not — it only means the address is syntactically a long-zero address.

**Exploit flow:**
1. Attacker identifies a deleted entity (e.g., a deleted contract with numeric ID `N`).
2. Attacker submits a transaction to the Hedera network with `ContractID.evmAddress = 0x000000000000000000000000<N as 8-byte big-endian>`.
3. The transaction enters the record stream and is processed by the importer.
4. `EntityIdServiceImpl.lookup(ContractID)` → `findByEvmAddress(evmAddress)` is called.
5. `DomainUtils.fromEvmAddress()` detects a long-zero address and returns `EntityId(shard, realm, N)` immediately.
6. `entityRepository.findByEvmAddress()` is never called; the deleted entity's ID is returned as valid.
7. The importer records the transaction as referencing the deleted entity, corrupting mirror node state.

**Why existing checks fail:** The `deleted <> true` guard exists only in the DB query at line 19–20 of `EntityRepository.java`. It is never reached for long-zero addresses. The `notify()` method (line 138) does check `entity.getDeleted()` before caching, but this is the write path, not the read path. The cache lookup at line 116–123 of `EntityIdServiceImpl` also does not check deletion status. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
The mirror node importer will associate transactions with deleted entities, corrupting the mirror node's database. Downstream consumers of the mirror node REST API (block explorers, wallets, dApps) will see transactions linked to entities that should not exist. In the web3 module, `ContractBytecodeReadableKVState.toEntityId()` has the same pattern (lines 54–55): a long-zero address bypasses `commonEntityAccessor.getEntityByEvmAddressAndTimestamp()` (which calls `findByEvmAddressAndDeletedIsFalse`) and directly fetches bytecode for a deleted contract, potentially enabling EVM execution against a deleted contract's code. [4](#0-3) 

### Likelihood Explanation
Any unprivileged user can submit a Hedera transaction with an arbitrary `ContractID.evmAddress` field. Long-zero addresses are a well-known Hedera convention (documented in the codebase itself). An attacker only needs to know the numeric ID of a deleted entity, which is publicly observable via the mirror node REST API. The attack is trivially repeatable and requires no special privileges or cryptographic material.

### Recommendation
In `EntityIdServiceImpl.findByEvmAddress()`, after `DomainUtils.fromEvmAddress()` returns a non-null `EntityId` for a long-zero address, perform a deletion check before returning it:

```java
private Optional<EntityId> findByEvmAddress(byte[] evmAddress, boolean throwRecoverableError) {
    var fromLongZero = DomainUtils.fromEvmAddress(evmAddress);
    if (fromLongZero != null) {
        // Verify the entity is not deleted before returning
        return entityRepository.findByIdAndDeletedIsFalse(fromLongZero.getId())
                .map(Entity::toEntityId)
                .or(() -> {
                    if (throwRecoverableError) {
                        Utility.handleRecoverableError("Entity not found or deleted for EVM address {}", ...);
                    }
                    return Optional.empty();
                });
    }
    return entityRepository.findByEvmAddress(evmAddress).map(EntityId::of);
}
```

Apply the same fix to `ContractBytecodeReadableKVState.toEntityId()` by routing long-zero addresses through `commonEntityAccessor.get(EntityId, timestamp)` (which calls `findByIdAndDeletedIsFalse`) instead of calling `DomainUtils.fromEvmAddress()` directly.

### Proof of Concept
1. Create and then delete a contract entity with numeric ID `N` (e.g., `N = 100`) in the Hedera network.
2. Confirm the entity is deleted: `GET /api/v1/contracts/0.0.100` returns `deleted: true`.
3. Submit a `ContractCall` transaction to the Hedera network with:
   ```
   ContractID.evmAddress = 0x0000000000000000000000000000000000000064  // 100 in hex
   ```
4. Wait for the mirror node importer to process the record stream.
5. Observe that `EntityIdServiceImpl.findByEvmAddress()` returns `EntityId(0, 0, 100)` for the deleted entity.
6. Confirm the transaction is recorded in the mirror node DB referencing entity ID `100` (deleted), bypassing the `deleted <> true` guard.
7. For the web3 path: call `eth_call` with `to: 0x0000000000000000000000000000000000000064` — `ContractBytecodeReadableKVState` will return the deleted contract's bytecode without any deletion check.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L169-178)
```java
    private Optional<EntityId> findByEvmAddress(byte[] evmAddress, boolean throwRecoverableError) {
        var id = Optional.ofNullable(DomainUtils.fromEvmAddress(evmAddress))
                .or(() -> entityRepository.findByEvmAddress(evmAddress).map(EntityId::of));

        if (id.isEmpty() && throwRecoverableError) {
            Utility.handleRecoverableError("Entity not found for EVM address {}", Hex.encodeHexString(evmAddress));
        }

        return id;
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java (L285-297)
```java
    public static EntityId fromEvmAddress(byte[] evmAddress) {
        final var commonProperties = CommonProperties.getInstance();

        try {
            if (isLongZeroAddress(evmAddress)) {
                final var num = Longs.fromByteArray(Arrays.copyOfRange(evmAddress, 12, 20));
                return EntityId.of(commonProperties.getShard(), commonProperties.getRealm(), num);
            }
        } catch (InvalidEntityException ex) {
            log.debug("Failed to parse long zero evm address into EntityId", ex);
        }
        return null;
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java (L19-20)
```java
    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L52-61)
```java
        } else if (contractID.hasEvmAddress()) {
            final var evmAddress = contractID.evmAddress().toByteArray();
            if (isLongZeroAddress(evmAddress)) {
                return DomainUtils.fromEvmAddress(evmAddress);
            } else {
                return commonEntityAccessor
                        .getEntityByEvmAddressAndTimestamp(evmAddress, Optional.empty())
                        .map(Entity::toEntityId)
                        .orElse(EntityId.EMPTY);
            }
```
