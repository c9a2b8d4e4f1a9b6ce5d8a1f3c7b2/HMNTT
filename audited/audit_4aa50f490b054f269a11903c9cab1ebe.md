### Title
GraphQL `account` Balance Reflects Spurious Errata=DELETE Transfers Due to Missing Errata Check in `SqlEntityListener.onCryptoTransfer`

### Summary

The `SqlEntityListener.onCryptoTransfer()` method unconditionally updates `entity.balance` for every crypto transfer it receives, including those marked `errata=DELETE`. Because `EntityRecordItemListener.insertTransferList()` marks spurious failed-transfer amounts as `errata=DELETE` but still forwards them to the entity listener, the denormalized `entity.balance` column in the `entity` table absorbs the spurious amounts. The GraphQL `account` query reads `entity.balance` directly from the `entity` table with no further filtering, so any unprivileged caller can receive an incorrect balance.

### Finding Description

**Code path:**

`EntityRecordItemListener.insertTransferList()` detects a "failed transfer" errata condition and marks the `CryptoTransfer` object as `errata=DELETE`, but unconditionally calls `entityListener.onCryptoTransfer(cryptoTransfer)` for every transfer regardless of that flag: [1](#0-0) 

`SqlEntityListener.onCryptoTransfer()` then updates `entity.balance` with the transfer amount **without inspecting `cryptoTransfer.getErrata()`**: [2](#0-1) 

The GraphQL `AccountController.balance()` resolver reads the balance directly from the `Account` view-model, which is mapped 1-to-1 from the `entity.balance` column: [3](#0-2) 

`EntityServiceImpl.getByIdAndType()` fetches the `Entity` row via a plain `findById`, with no post-query errata adjustment: [4](#0-3) 

**Root cause:** The errata guard exists only in the `crypto_transfer` table row (correctly set to `DELETE`) and in queries that explicitly filter on `errata <> 'DELETE'` (e.g., `BalanceReconciliationService`, `rosetta/app/persistence/account.go`, `web3/AccountBalanceRepository`). The `entity.balance` denormalized column is updated by `SqlEntityListener` without that guard, so it diverges from the correct value whenever errata=DELETE transfers are processed with `trackBalance=true`. [5](#0-4) 

`InitializeEntityBalanceMigration` does apply the filter when it initialises `entity.balance` from snapshots: [6](#0-5) 

However, this migration runs once at startup (before the importer begins streaming). When the importer subsequently processes the historical errata transactions in real-time, `SqlEntityListener.onCryptoTransfer()` re-applies the spurious amounts to `entity.balance`, overwriting the correctly initialised value.

`ErrataMigration.doMigrate()` temporarily sets `trackBalance=false` to avoid this during its own SQL updates, but that guard is not present during normal importer streaming: [7](#0-6) 

### Impact Explanation

Any caller of the public GraphQL endpoint `account(input: {entityId: {shard: 0, realm: 0, num: N}})` receives the value of `entity.balance` directly. For the 1 177 accounts affected by the "Failed Transfers in Record" errata (mainnet, 2019-09-14 – 2019-10-03), the returned balance includes amounts from transfers that never actually settled, misrepresenting the true on-chain state. This is a data-integrity / information-accuracy issue exposed to all unauthenticated users of the GraphQL API. [8](#0-7) 

### Likelihood Explanation

The condition is triggered on any mirror-node deployment that:
1. Starts the importer against a fresh (or re-initialised) database and streams mainnet data from genesis, **or**
2. Encounters any future errata scenario where `insertTransferList` marks transfers `errata=DELETE` while `trackBalance=true`.

No authentication is required to exploit the GraphQL endpoint. The query is trivial to construct (as shown in the project's own smoke-test documentation): [9](#0-8) 

### Recommendation

Add an errata guard in `SqlEntityListener.onCryptoTransfer()` before updating `entity.balance`:

```java
@Override
public void onCryptoTransfer(CryptoTransfer cryptoTransfer) throws ImporterException {
    if (entityProperties.getPersist().isTrackBalance()
            && cryptoTransfer.getErrata() != ErrataType.DELETE) {   // <-- add this guard
        var entity = new Entity();
        entity.setId(cryptoTransfer.getEntityId());
        entity.setBalance(cryptoTransfer.getAmount());
        entity.setBalanceTimestamp(cryptoTransfer.getConsensusTimestamp());
        onEntity(entity);
    }
    context.add(cryptoTransfer);
}
```

Additionally, add a follow-up migration (similar to `InitializeEntityBalanceMigration`) that recomputes `entity.balance` for all accounts whose balance was corrupted by previously processed errata=DELETE transfers.

### Proof of Concept

**Preconditions:**
- A mirror-node instance configured against mainnet, with `trackBalance=true` (default), streaming from genesis (fresh database).

**Steps:**
1. Start the importer. `InitializeEntityBalanceMigration` runs and sets `entity.balance` correctly (no errata=DELETE rows exist yet).
2. The importer streams mainnet record files. When it reaches the 2019-09-14 – 2019-10-03 window, `insertTransferList()` marks the spurious transfers `errata=DELETE` and forwards them to `SqlEntityListener.onCryptoTransfer()`.
3. `SqlEntityListener.onCryptoTransfer()` calls `onEntity(entity)` with the spurious amount, incrementing `entity.balance` by the erroneous value.
4. Query the GraphQL endpoint:
   ```bash
   curl -X POST http://<mirror-node>:8083/graphql/alpha \
     -H 'Content-Type: application/json' \
     -d '{"query":"{account(input:{entityId:{shard:0,realm:0,num:N}}){balance}}"}'
   ```
5. The returned `balance` includes the spurious transfer amounts rather than the correct settled balance, confirming the errata=DELETE transfers were not excluded from `entity.balance`.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/entity/EntityRecordItemListener.java (L302-327)
```java
        boolean failedTransfer =
                !recordItem.isSuccessful() && body.hasCryptoTransfer() && consensusTimestamp < 1577836799000000000L;

        for (int i = 0; i < transferList.getAccountAmountsCount(); ++i) {
            var aa = transferList.getAccountAmounts(i);
            var account = EntityId.of(aa.getAccountID());
            CryptoTransfer cryptoTransfer = new CryptoTransfer();
            cryptoTransfer.setAmount(aa.getAmount());
            cryptoTransfer.setConsensusTimestamp(consensusTimestamp);
            cryptoTransfer.setEntityId(account.getId());
            cryptoTransfer.setIsApproval(false);
            cryptoTransfer.setPayerAccountId(payerAccountId);

            AccountAmount accountAmountInsideBody = null;
            if (cryptoTransfer.getAmount() < 0 || failedTransfer) {
                accountAmountInsideBody = findAccountAmount(aa, body);
            }

            if (accountAmountInsideBody != null) {
                cryptoTransfer.setIsApproval(accountAmountInsideBody.getIsApproval());
                if (failedTransfer) {
                    cryptoTransfer.setErrata(ErrataType.DELETE);
                }
            }

            entityListener.onCryptoTransfer(cryptoTransfer);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/entity/sql/SqlEntityListener.java (L162-172)
```java
    public void onCryptoTransfer(CryptoTransfer cryptoTransfer) throws ImporterException {
        if (entityProperties.getPersist().isTrackBalance()) {
            var entity = new Entity();
            entity.setId(cryptoTransfer.getEntityId());
            entity.setBalance(cryptoTransfer.getAmount());
            entity.setBalanceTimestamp(cryptoTransfer.getConsensusTimestamp());
            onEntity(entity);
        }

        context.add(cryptoTransfer);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L60-63)
```java
    @SchemaMapping
    Long balance(@Argument @Valid HbarUnit unit, Account account) {
        return convertCurrency(unit, account.getBalance());
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/reconciliation/BalanceReconciliationService.java (L55-58)
```java
    private static final String CRYPTO_TRANSFER_QUERY = """
                    select entity_id, sum(amount) balance from crypto_transfer
                    where consensus_timestamp > ? and consensus_timestamp <= ? and (errata is null or errata <> 'DELETE')
                    group by entity_id""";
```

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/InitializeEntityBalanceMigration.java (L26-29)
```java
              from crypto_transfer
              where consensus_timestamp > :fromTimestamp and consensus_timestamp <= :toTimestamp and
                (errata is null or errata <> 'DELETE')
              group by entity_id
```

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/ErrataMigration.java (L116-129)
```java
            boolean entityHistory = entityProperties.getPersist().isEntityHistory();
            boolean trackBalance = entityProperties.getPersist().isTrackBalance();
            entityProperties.getPersist().setEntityHistory(false);
            entityProperties.getPersist().setTrackBalance(false);

            try {
                transactionOperationsProvider.getObject().executeWithoutResult(t -> {
                    balanceFileAdjustment();
                    spuriousTransfers();
                    missingTransactions();
                });
            } finally {
                entityProperties.getPersist().setTrackBalance(trackBalance);
                entityProperties.getPersist().setEntityHistory(entityHistory);
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L14-15)
```text
    "The balance of the accountable entity. Defaults to tinybars."
    balance(unit: HbarUnit = TINYBAR): Long
```

**File:** docs/graphql/README.md (L33-36)
```markdown
```bash
curl -X POST http://localhost:8083/graphql/alpha -H 'Content-Type: application/json' \
  -d '{"query": "{account(input: {entityId: {shard: 0, realm: 0, num: 2}}) { balance }}"}'
```
```
