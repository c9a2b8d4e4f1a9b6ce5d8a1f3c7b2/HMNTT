### Title
Missing `deleted is not true` Filter in `entity_history` Branch of `findActiveByEvmAddressOrAliasAndTimestamp` Allows Deleted Entity State to Be Returned

### Summary
The `entity_history` branch of `findActiveByEvmAddressOrAliasAndTimestamp` (and the parallel `findActiveByEvmAddressAndTimestamp`) omits the `deleted is not true` guard that is present in the `entity` branch and in the equivalent `findActiveByIdAndTimestamp` query. When a caller supplies a `blockTimestamp` equal to `lower(eh.timestamp_range)` of a deleted `entity_history` record, and the current `entity` row is also deleted (so the `entity` branch returns nothing), the deleted history row wins the final `ORDER BY timestamp_range DESC LIMIT 1` and is returned as the result. This causes the mirror node to export incorrect deleted-entity state for historical queries.

### Finding Description

**Exact code location**

`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 95–121 (`findActiveByEvmAddressOrAliasAndTimestamp`) and lines 59–85 (`findActiveByEvmAddressAndTimestamp`). [1](#0-0) 

The `entity_history` sub-query (lines 110–117) has no `deleted is not true` predicate. Contrast with `findActiveByIdAndTimestamp` (lines 136–155), which correctly adds that predicate to both branches: [2](#0-1) 

**Root cause**

The `entity_cte` resolves the entity ID from the `entity` table without checking `deleted`: [3](#0-2) 

So even when the current entity row has `deleted = true`, the CTE still returns its ID. The `entity` branch then correctly returns nothing (line 106: `e.deleted is not true`), but the `entity_history` branch has no such guard, so it returns the most recent history row whose `lower(timestamp_range) <= blockTimestamp` — regardless of whether that row itself is marked deleted.

**Exploit flow**

Preconditions (realistic on Hedera mainnet — entities can be deleted and recreated):

| Time | Event | `entity` table | `entity_history` table |
|------|-------|----------------|------------------------|
| T0 | Created | `[T0,∞) deleted=false` | — |
| T1 | Deleted | `[T1,∞) deleted=true` | `[T0,T1) deleted=false` |
| T2 | Recreated | `[T2,∞) deleted=false` | `[T0,T1) deleted=false`, `[T1,T2) deleted=true` |
| T3 | Deleted again | `[T3,∞) deleted=true` | `[T0,T1) deleted=false`, `[T1,T2) deleted=true`, `[T2,T3) deleted=false` |

Attacker submits `blockTimestamp = T1`:

1. `entity_cte` → finds entity ID (created_timestamp T0 ≤ T1).
2. `entity` branch → `deleted=true` → returns **empty**.
3. `entity_history` branch → candidates: `[T0,T1)` (lower=T0≤T1) and `[T1,T2)` (lower=T1≤T1). `ORDER BY lower(timestamp_range) DESC LIMIT 1` picks `[T1,T2)` — the deleted history row.
4. Final `ORDER BY timestamp_range DESC LIMIT 1` → returns the `[T1,T2) deleted=true` row.

Simpler (and more impactful) variant — entity deleted once, never recreated:

Attacker submits `blockTimestamp = T1` (or any value ≥ T0):
- `entity` branch → empty (deleted=true).
- `entity_history` branch → returns `[T0,T1) deleted=false`.
- Result: **deleted entity appears active** (deleted=false).

**Why existing checks fail**

The existing test coverage at lines 366–382 only creates an `entity_history` row via `persistEntityHistoryWithDeleted()` *without* a corresponding `entity` row: [4](#0-3) 

Without an `entity` row, `entity_cte` returns NULL and both branches return empty — the test passes but does not exercise the real attack path. Additionally, the test uses `timestampLower - 1` (line 371, 380), which makes `lower(T) <= T-1` false, so the history row is never reached even if the CTE did return an ID. [5](#0-4) 

### Impact Explanation

`findActiveByEvmAddressOrAliasAndTimestamp` is called by `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` (line 48), which is the entry point for alias/EVM-address resolution in all historical EVM calls: [6](#0-5) 

This feeds directly into `AliasesReadableKVState.readFromDataSource()` (line 59), which resolves `AccountID` for the EVM state: [7](#0-6) 

Concrete consequences:
- A deleted entity is resolved as active in historical `eth_call` / `eth_getBalance` / contract-call queries, returning stale or incorrect balances and state.
- A deleted entity_history row (deleted=true) is returned as a non-empty `Optional`, causing callers that do not re-check the `deleted` flag to treat the entity as present.
- Mirror node exports incorrect historical entity state, undermining the integrity guarantees of the mirror node API.

### Likelihood Explanation

No privilege is required. Any user of the public JSON-RPC endpoint can issue an `eth_call` or `eth_getBalance` with an arbitrary `blockNumber` (which maps to a `blockTimestamp`). The attacker only needs to know the EVM address or alias of a previously deleted account (publicly visible on-chain) and the block number at which the deletion occurred (also publicly visible). Entity deletion and recreation is a normal Hedera operation (e.g., account expiry and re-creation). The attack is fully repeatable and deterministic.

### Recommendation

Add `and eh.deleted is not true` to the `entity_history` sub-query in both affected methods, mirroring the fix already present in `findActiveByIdAndTimestamp`:

```sql
-- findActiveByEvmAddressOrAliasAndTimestamp (line 110-117)
(
    select *
    from entity_history eh
    where lower(eh.timestamp_range) <= ?2
    and eh.id = (select id from entity_cte)
    and eh.deleted is not true          -- ADD THIS
    order by lower(eh.timestamp_range) desc
    limit 1
)
```

Apply the same fix to `findActiveByEvmAddressAndTimestamp` (lines 74–81). Add integration tests that pair a deleted `entity` row with a deleted `entity_history` row and assert that querying with `blockTimestamp = lower(history.timestamp_range)` returns empty.

### Proof of Concept

```sql
-- Setup
INSERT INTO entity (id, evm_address, alias, created_timestamp, deleted, timestamp_range)
  VALUES (42, '\xDEAD...', '\xBEEF...', 1000, true, '[3000,)');

INSERT INTO entity_history (id, evm_address, alias, created_timestamp, deleted, timestamp_range)
  VALUES (42, '\xDEAD...', '\xBEEF...', 1000, false, '[1000,2000)'),
         (42, '\xDEAD...', '\xBEEF...', 1000, true,  '[2000,3000)'),  -- deleted history row
         (42, '\xDEAD...', '\xBEEF...', 1000, false, '[3000,4000)');  -- wait, entity is deleted at 3000

-- Attack: submit blockTimestamp = 2000 (= lower of the deleted history row)
-- Expected: empty (entity is deleted at this point in history)
-- Actual: returns the [2000,3000) row with deleted=true

WITH entity_cte AS (
    SELECT id FROM entity
    WHERE created_timestamp <= 2000
      AND (evm_address = '\xDEAD...' OR alias = '\xBEEF...')
    ORDER BY created_timestamp DESC LIMIT 1
)
(SELECT * FROM entity e
 WHERE e.deleted IS NOT TRUE AND e.id = (SELECT id FROM entity_cte))
UNION ALL
(SELECT * FROM entity_history eh
 WHERE lower(eh.timestamp_range) <= 2000
   AND eh.id = (SELECT id FROM entity_cte)
 ORDER BY lower(eh.timestamp_range) DESC LIMIT 1)
ORDER BY timestamp_range DESC LIMIT 1;
-- Returns: id=42, deleted=true, timestamp_range=[2000,3000)  ← should be empty
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L96-102)
```java
            with entity_cte as (
                select id
                from entity
                where created_timestamp <= ?2 and (evm_address = ?1 or alias = ?1)
                order by created_timestamp desc
                limit 1
            )
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L109-117)
```java
            union all
            (
                select *
                from entity_history eh
                where lower(eh.timestamp_range) <= ?2
                and eh.id = (select id from entity_cte)
                order by lower(eh.timestamp_range) desc
                limit 1
            )
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L143-151)
```java
                    union all
                    (
                        select *
                        from entity_history
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                        order by lower(timestamp_range) desc
                        limit 1
                    )
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/EntityRepositoryTest.java (L367-382)
```java
    void findHistoricalEntityByEvmAddressOrAliasAndTimestampRangeAndDeletedTrueCallWithAlias() {
        final var entityHistory = persistEntityHistoryWithDeleted();

        assertThat(entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(
                        entityHistory.getAlias(), entityHistory.getTimestampLower() - 1))
                .isEmpty();
    }

    @Test
    void findHistoricalEntityByEvmAddressOrAliasAndTimestampRangeAndDeletedTrueCallWithEvmAddress() {
        final var entityHistory = persistEntityHistoryWithDeleted();

        assertThat(entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(
                        entityHistory.getEvmAddress(), entityHistory.getTimestampLower() - 1))
                .isEmpty();
    }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/EntityRepositoryTest.java (L547-549)
```java
    private EntityHistory persistEntityHistoryWithDeleted() {
        return domainBuilder.entityHistory().customize(e -> e.deleted(true)).persist();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/AliasesReadableKVState.java (L57-67)
```java
    protected AccountID readFromDataSource(@NonNull ProtoBytes alias) {
        final var timestamp = ContractCallContext.get().getTimestamp();
        final var entity = commonEntityAccessor.get(alias.value(), timestamp);
        return entity.map(e -> {
                    final var account = accountFromEntity(e, timestamp);
                    final var accountID = account.accountId();
                    // Put the account in the account num cache.
                    aliasedAccountCacheManager.putAccountNum(accountID, account);
                    return accountID;
                })
                .orElse(null);
```
