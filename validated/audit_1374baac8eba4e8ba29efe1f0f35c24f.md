I have now verified all the key claims against the actual code. Let me summarize my findings before rendering the verdict.

**Verified facts:**

1. `EntityIdServiceImpl.findByEvmAddress` (lines 169-178) uses `Optional.ofNullable(...).or(...)` — the DB branch is only reached if `DomainUtils.fromEvmAddress` returns `null`. [1](#0-0) 

2. `DomainUtils.fromEvmAddress` (lines 285-297) returns a non-null `EntityId` for any long-zero address with no deletion check. [2](#0-1) 

3. The bypassed DB query enforces `deleted <> true`. [3](#0-2) 

4. `lookupContractEvmAddressDeleted` only tests a contract with a *custom* (non-long-zero) EVM address — it goes through the DB path and correctly returns empty. [4](#0-3) 

5. `lookupAccountEvmAddress` confirms a long-zero address resolves to an `EntityId` with no DB entity present at all. [5](#0-4) 

6. `notify()` correctly skips deleted entities before warming the cache, but this does not help because the long-zero path bypasses both cache and DB. [6](#0-5) 

7. `EntityRecordItemListener.onItem` uses the resolved `entityId` to build and persist the `Transaction` record unconditionally (including for failed transactions). [7](#0-6) 

8. `handleRecoverableError` escalates to `ParserException` when `HIERO_MIRROR_IMPORTER_PARSER_HALTONERROR=true`. **However**, for the long-zero path, `id` is never empty, so `handleRecoverableError` is **not** triggered by this specific code path — the importer-halt scenario in the report is speculative and incorrect. [8](#0-7) [9](#0-8) 

---

Audit Report

## Title
Long-Zero EVM Address Bypasses Deletion Check, Causing Inconsistent Entity Resolution in Mirror Node Importer

## Summary
`EntityIdServiceImpl.findByEvmAddress` unconditionally short-circuits the database lookup when the supplied 20-byte EVM address is in long-zero format (first 12 bytes all zero), returning a derived `EntityId` without consulting the database. The database path enforces `deleted <> true`, but the long-zero derivation path in `DomainUtils.fromEvmAddress` has no such guard. Any user can submit a Hedera transaction referencing a deleted entity by its long-zero EVM address, causing the mirror node importer to resolve and record the transaction against the deleted entity, producing inconsistent transaction history.

## Finding Description

**Exact code path:**

`EntityIdServiceImpl.findByEvmAddress` — `importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java`, lines 169–178:

```java
private Optional<EntityId> findByEvmAddress(byte[] evmAddress, boolean throwRecoverableError) {
    var id = Optional.ofNullable(DomainUtils.fromEvmAddress(evmAddress))   // line 170
            .or(() -> entityRepository.findByEvmAddress(evmAddress).map(EntityId::of)); // line 171
    ...
}
```

The `.or(...)` lambda is only evaluated if `DomainUtils.fromEvmAddress` returns `null`. For any long-zero address it returns a non-null `EntityId`, so the lambda — and therefore the database — is never reached. [1](#0-0) 

`DomainUtils.fromEvmAddress` — `common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java`, lines 285–297:

```java
public static EntityId fromEvmAddress(byte[] evmAddress) {
    if (isLongZeroAddress(evmAddress)) {
        final var num = Longs.fromByteArray(Arrays.copyOfRange(evmAddress, 12, 20));
        return EntityId.of(commonProperties.getShard(), commonProperties.getRealm(), num);
    }
    return null;
}
``` [2](#0-1) 

`isLongZeroAddress` returns `true` for any 20-byte array whose first 12 bytes are all zero. [10](#0-9) 

The database query that is bypassed (`importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java`, line 19–20):

```sql
select id from entity where evm_address = ?1 and deleted <> true
``` [3](#0-2) 

**Root cause / failed assumption:** The code assumes that if an address is in long-zero format, the entity with the derived number is always valid and active. This assumption is wrong: entity `0.0.N` can be deleted, yet the long-zero address `0x000000000000000000000000[8-byte N]` will still resolve to `EntityId(0.0.N)` without any existence or deletion check.

**Why existing checks fail:** The test `lookupContractEvmAddressDeleted` only covers a deleted contract with a custom (non-long-zero) EVM address — it goes through the DB path and correctly returns empty. [4](#0-3) 

There is no test for a deleted entity whose EVM address is in long-zero format. The `lookupAccountEvmAddress` test confirms that a long-zero address resolves to an `EntityId` with no DB entity present at all. [5](#0-4) 

The `notify()` method correctly skips deleted entities before warming the cache, but this does not help: the long-zero path in `findByEvmAddress` bypasses both the cache and the DB, so a cache miss still resolves to the deleted entity. [6](#0-5) 

## Impact Explanation

The mirror node importer processes every confirmed Hedera transaction, including failed ones. When a transaction referencing a deleted entity by long-zero EVM address is processed, `EntityIdServiceImpl.findByEvmAddress` returns the deleted entity's `EntityId`. This `EntityId` is then used by `EntityRecordItemListener.onItem` to build and persist the `Transaction` record, associating the transaction with the deleted entity in the mirror node's database. [7](#0-6) 

The result is a data integrity inconsistency: for a deleted entity with a custom EVM address, the mirror node correctly returns empty and records no entity association; for the same deleted entity referenced by its long-zero address, the mirror node incorrectly records the transaction against the deleted entity. Applications and block explorers relying on the mirror node REST API for transaction history will receive inconsistent results depending on which address format was used.

Note: The claim that this can halt the importer via `handleRecoverableError` / `ParserException` is **incorrect**. The `handleRecoverableError` call in `findByEvmAddress` is only triggered when `id.isEmpty()`. For a long-zero address, `id` is always non-empty (the derived `EntityId` is returned), so the importer-halt path is never reached through this specific code path. [9](#0-8) 

## Likelihood Explanation

No special privileges are required. Any Hedera user can:
1. Identify a deleted entity number `N` (publicly visible via the mirror node REST API).
2. Submit any contract-call transaction to the Hedera network with a `ContractID.evm_address` set to the 20-byte long-zero address for `N`.
3. The network records the transaction as failed; the mirror node importer processes it and incorrectly associates it with the deleted entity.

This is repeatable, cheap (only transaction fees), and requires no insider access or cryptographic capability.

## Recommendation

In `EntityIdServiceImpl.findByEvmAddress`, after `DomainUtils.fromEvmAddress` returns a non-null `EntityId` for a long-zero address, add a database existence and deletion check before returning it. For example:

```java
private Optional<EntityId> findByEvmAddress(byte[] evmAddress, boolean throwRecoverableError) {
    var longZeroId = DomainUtils.fromEvmAddress(evmAddress);
    Optional<EntityId> id;
    if (longZeroId != null) {
        // Verify the entity exists and is not deleted
        id = entityRepository.findById(longZeroId.getId())
                .filter(e -> e.getDeleted() == null || !e.getDeleted())
                .map(EntityId::of);
        if (id.isEmpty()) {
            id = Optional.of(longZeroId); // fallback: entity not yet in DB (e.g. pre-genesis)
            // OR: treat as not found, depending on desired semantics
        }
    } else {
        id = entityRepository.findByEvmAddress(evmAddress).map(EntityId::of);
    }
    ...
}
```

Alternatively, add a dedicated `findByIdAndNotDeleted` query to `EntityRepository` and use it in the long-zero branch. A regression test covering a deleted entity referenced by its long-zero EVM address should also be added to `EntityIdServiceImplTest`.

## Proof of Concept

1. Create entity `0.0.500` on the Hedera network and then delete it.
2. Confirm via the mirror node REST API that entity `0.0.500` has `deleted: true`.
3. Construct a `ContractCallTransaction` with `ContractID.evm_address = 0x00000000000000000000000000000000000001F4` (long-zero for num=500).
4. Submit the transaction; the network returns `CONTRACT_DELETED`.
5. After the mirror node importer processes the record file, query the mirror node for transactions associated with entity `0.0.500`.
6. Observe that the failed transaction is recorded with `entity_id = 0.0.500`, while an equivalent transaction using a custom EVM address for the same deleted entity would record `entity_id = null` / empty.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L137-139)
```java
    public void notify(Entity entity) {
        if (entity == null || (entity.getDeleted() != null && entity.getDeleted())) {
            return;
```

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

**File:** common/src/main/java/org/hiero/mirror/common/util/DomainUtils.java (L405-411)
```java
    public static boolean isLongZeroAddress(byte[] evmAddress) {
        if (evmAddress == null || evmAddress.length != EVM_ADDRESS_LENGTH) {
            return false;
        }

        return Arrays.equals(MIRROR_PREFIX, 0, 12, evmAddress, 0, 12);
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java (L19-20)
```java
    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** importer/src/test/java/org/hiero/mirror/importer/domain/EntityIdServiceImplTest.java (L277-284)
```java
    void lookupContractEvmAddressDeleted() {
        Entity contract = domainBuilder
                .entity()
                .customize(e -> e.alias(null).deleted(true).type(CONTRACT))
                .persist();
        var contractId = getProtoContractId(contract);
        assertThat(entityIdService.lookup(contractId)).isEmpty();
    }
```

**File:** importer/src/test/java/org/hiero/mirror/importer/domain/EntityIdServiceImplTest.java (L415-422)
```java
    void lookupAccountEvmAddress() {
        AccountID accountId = AccountID.newBuilder()
                .setAlias(DomainUtils.fromBytes(PARSABLE_EVM_ADDRESS))
                .build();

        assertThat(entityIdService.lookup(accountId))
                .hasValue(EntityId.of(commonProperties.getShard(), commonProperties.getRealm(), EVM_ADDRESS_NUM));
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/entity/EntityRecordItemListener.java (L121-163)
```java
        Transaction transaction = buildTransaction(entityId, recordItem);
        transactionHandler.updateTransaction(transaction, recordItem);

        // Insert transfers even on failure
        insertTransferList(recordItem);
        insertStakingRewardTransfers(recordItem);

        // handle scheduled transaction, even on failure
        if (transaction.isScheduled()) {
            onScheduledTransaction(recordItem);
        }

        if (recordItem.isSuccessful()) {
            if (persistProperties.getTransactionSignatures().contains(transactionType)) {
                insertTransactionSignatures(
                        transaction.getEntityId(),
                        recordItem.getConsensusTimestamp(),
                        recordItem.getSignatureMap().getSigPairList());
            }

            // Only add non-fee transfers on success as the data is assured to be valid
            processItemizedTransfers(recordItem, transaction);
        }

        // Errata records can fail with FAIL_INVALID but still have items in the record committed to state.
        if (recordItem.isSuccessful() || recordItem.getTransactionStatus() == ResponseCodeEnum.FAIL_INVALID_VALUE) {
            insertAutomaticTokenAssociations(recordItem);
            // Record token transfers can be populated for multiple transaction types
            insertTokenTransfers(recordItem, transaction);
            insertAssessedCustomFees(recordItem);
        }

        contractResultService.process(recordItem, transaction);

        var entityTransactions = recordItem.getEntityTransactions();
        if (!entityTransactions.isEmpty()) {
            entityListener.onEntityTransactions(entityTransactions.values());
        }
        var contractTransactions = recordItem.populateContractTransactions();
        if (!contractTransactions.isEmpty()) {
            entityListener.onContractTransactions(contractTransactions);
        }
        entityListener.onTransaction(transaction);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/util/Utility.java (L220-231)
```java
    public static void handleRecoverableError(String message, Object... args) {
        var haltOnError = Boolean.parseBoolean(System.getProperty(HALT_ON_ERROR_PROPERTY));

        if (haltOnError) {
            var formattingTuple = MessageFormatter.arrayFormat(message, args);
            var throwable = formattingTuple.getThrowable();
            var formattedMessage = formattingTuple.getMessage();
            throw new ParserException(formattedMessage, throwable);
        } else {
            log.error(RECOVERABLE_ERROR + message, args);
        }
    }
```
