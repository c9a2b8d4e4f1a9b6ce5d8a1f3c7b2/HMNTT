### Title
Missing Alias Resolution for `autoRenewAccount` in `ConsensusCreateTopicTransactionHandler.doUpdateEntity()` Causes Incorrect Mirror Node Records

### Summary
`ConsensusCreateTopicTransactionHandler.doUpdateEntity()` resolves the `autoRenewAccount` field using `EntityId.of(transactionBody.getAutoRenewAccount())`, which only reads `getAccountNum()` from the protobuf `AccountID` and silently returns `EntityId.EMPTY` (id=0) when the account is specified as an alias. Every other analogous handler in the codebase uses `entityIdService.lookup()` for this field, which correctly resolves aliases. Any unprivileged user can trigger this by submitting a `ConsensusCreateTopic` transaction with `autoRenewAccount` set as an alias-based `AccountID`.

### Finding Description

**Exact code path:**

`ConsensusCreateTopicTransactionHandler.java`, `doUpdateEntity()`, lines 40–44:

```java
if (transactionBody.hasAutoRenewAccount()) {
    var autoRenewAccountId = EntityId.of(transactionBody.getAutoRenewAccount());  // BUG
    entity.setAutoRenewAccountId(autoRenewAccountId.getId());
    recordItem.addEntityId(autoRenewAccountId);
}
```

`EntityId.of(AccountID)` is defined as:

```java
public static EntityId of(AccountID accountID) {
    return of(accountID.getShardNum(), accountID.getRealmNum(), accountID.getAccountNum());
}
```

When `AccountID` is set with an alias (i.e., `accountID.getAccountCase() == ALIAS`), `getAccountNum()` returns `0`, so `EntityId.of()` returns `EntityId.EMPTY` (encoded id = 0).

**Root cause:** The handler bypasses `entityIdService.lookup()`, which is the only path that performs alias-to-numeric-ID resolution (via cache and DB lookup). The failed assumption is that `autoRenewAccount` will always be specified as a numeric `AccountID`; the HAPI protobuf `AccountID` supports both `accountNum` and `alias` forms.

**Contrast with all sibling handlers** — every other handler that processes `autoRenewAccount` uses `entityIdService.lookup()`:
- `ConsensusUpdateTopicTransactionHandler.doUpdateEntity()` lines 43–54: `entityIdService.lookup(transactionBody.getAutoRenewAccount())`
- `ContractCreateTransactionHandler.doUpdateEntity()` lines 75–85: `entityIdService.lookup(transactionBody.getAutoRenewAccountId())`
- `ContractUpdateTransactionHandler.doUpdateEntity()` lines 62–73: `entityIdService.lookup(transactionBody.getAutoRenewAccountId())`
- `TokenCreateTransactionHandler.doUpdateEntity()` lines 61–71: `entityIdService.lookup(transactionBody.getAutoRenewAccount())`
- `TokenUpdateTransactionHandler.doUpdateEntity()` lines 46–57: `entityIdService.lookup(transactionBody.getAutoRenewAccount())`

`ConsensusCreateTopicTransactionHandler` is the sole outlier.

**Exploit flow:**
1. Attacker holds account `0.0.X` that has an ECDSA alias (or any alias).
2. Attacker submits `ConsensusCreateTopic` with `autoRenewAccount` set as `AccountID{alias: <alias_bytes>}` instead of `AccountID{accountNum: X}`.
3. Consensus node validates the transaction (alias resolves to `0.0.X`), transaction succeeds, record stream is written with the original transaction body (alias form preserved).
4. Mirror node importer calls `doUpdateEntity()`. `EntityId.of(aliasAccountID)` returns `EntityId.EMPTY` (id=0).
5. `entity.setAutoRenewAccountId(0)` — the topic entity row in the mirror DB records `auto_renew_account_id = 0` instead of the actual account's encoded id.
6. `recordItem.addEntityId(EntityId.EMPTY)` — the entity transaction record for the actual `autoRenewAccount` (`0.0.X`) is never emitted; the record for entity id=0 may be emitted instead (depending on predicate).

**Why existing checks fail:** `transactionBody.hasAutoRenewAccount()` only tests field presence (protobuf `has*` semantics), not whether the `AccountID` is in numeric or alias form. There is no guard against alias-based input anywhere in this handler.

### Impact Explanation

The mirror node's `entity` table stores `auto_renew_account_id = 0` for any topic created with an alias-based `autoRenewAccount`. REST API consumers querying topic details receive a wrong (or null) `auto_renew_account` field. The entity transaction record for the actual `autoRenewAccount` is absent from the mirror node export, breaking downstream analytics and audit trails that rely on entity transaction tracking. This is a data-integrity corruption that is silent (no error is thrown, no log is emitted) and permanent for the affected topic row.

### Likelihood Explanation

Any unprivileged user with a Hedera account that has an alias (standard for ECDSA-key accounts, which are common) can trigger this with a single `ConsensusCreateTopic` transaction. No special permissions, no admin keys, no coordination required. The HAPI SDK allows specifying `AccountID` by alias. The attack is trivially repeatable for every new topic creation.

### Recommendation

Replace the direct `EntityId.of()` call with `entityIdService.lookup()`, mirroring the pattern used in `ConsensusUpdateTopicTransactionHandler`:

```java
if (transactionBody.hasAutoRenewAccount()) {
    entityIdService
        .lookup(transactionBody.getAutoRenewAccount())
        .ifPresentOrElse(
            accountId -> {
                entity.setAutoRenewAccountId(accountId.getId());
                recordItem.addEntityId(accountId);
            },
            () -> Utility.handleRecoverableError(
                "Invalid autoRenewAccountId at {}", recordItem.getConsensusTimestamp()));
}
```

Add a test analogous to `ConsensusUpdateTopicTransactionHandlerTest.updateTransactionSuccessfulAutoRenewAccountAlias` for the create handler.

### Proof of Concept

1. Create an ECDSA account `0.0.X` with an alias on a Hedera testnet.
2. Construct a `ConsensusCreateTopicTransactionBody` with:
   ```
   autoRenewAccount = AccountID { alias: <ECDSA_alias_bytes_of_0.0.X> }
   ```
3. Sign and submit the transaction. Observe `SUCCESS` in the receipt.
4. Query the mirror node REST API: `GET /api/v1/topics/{new_topic_id}`.
5. Observe `auto_renew_account` is `null` or `0.0.0` instead of `0.0.X`.
6. Query entity transactions for `0.0.X` at the consensus timestamp of the create transaction — no record exists.

The bug is confirmed by comparing with `ConsensusUpdateTopicTransactionHandlerTest` line 113–145, which explicitly tests alias resolution for the update handler (and passes), while no equivalent test exists for the create handler.