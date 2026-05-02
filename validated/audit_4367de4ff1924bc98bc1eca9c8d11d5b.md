I have verified all the claims in the report against the actual code. Let me confirm the key facts:

Audit Report

## Title
Missing `deleted is not true` Filter in `entity_history` Branch of `findActiveByEvmAddressOrAliasAndTimestamp` and `findActiveByEvmAddressAndTimestamp`

## Summary
The `entity_history` sub-query branch in both `findActiveByEvmAddressOrAliasAndTimestamp` and `findActiveByEvmAddressAndTimestamp` omits the `deleted is not true` predicate that is present in the `entity` branch of those same queries and in both branches of the equivalent `findActiveByIdAndTimestamp`. This allows a deleted `entity_history` row to be returned as the result of a historical alias/EVM-address lookup, causing callers such as `AliasesReadableKVState.readFromDataSource()` — which do not re-check the `deleted` flag — to treat a deleted entity as active.

## Finding Description

**Exact location**

`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`

The `entity_history` branch of `findActiveByEvmAddressOrAliasAndTimestamp` (lines 110–117) has no `deleted is not true` predicate: [1](#0-0) 

The same omission exists in `findActiveByEvmAddressAndTimestamp` (lines 75–81): [2](#0-1) 

Contrast with `findActiveByIdAndTimestamp` (lines 136–155), which correctly adds `deleted is not true` to **both** the `entity` branch (line 141) and the `entity_history` branch (line 148): [3](#0-2) 

**Root cause**

The `entity_cte` resolves the entity ID from the `entity` table without checking `deleted`: [4](#0-3) 

So even when the current entity row has `deleted = true`, the CTE still returns its ID. The `entity` branch correctly returns nothing (`e.deleted is not true`, line 106), but the `entity_history` branch has no such guard and returns the most recent history row whose `lower(timestamp_range) <= blockTimestamp` — regardless of whether that row is marked deleted.

**Exploit flow (simple, most impactful)**

| Time | Event | `entity` table | `entity_history` table |
|------|-------|----------------|------------------------|
| T0 | Created | `[T0,∞) deleted=false` | — |
| T1 | Deleted | `[T1,∞) deleted=true` | `[T0,T1) deleted=false` |

Attacker submits `blockTimestamp = T1`:
1. `entity_cte` → finds entity ID (`created_timestamp T0 ≤ T1`).
2. `entity` branch → `deleted=true` → returns **empty**.
3. `entity_history` branch → `[T0,T1)` row: `lower(T0) ≤ T1` → **TRUE** → returns `deleted=false`.
4. Final `ORDER BY timestamp_range DESC LIMIT 1` → returns the `[T0,T1) deleted=false` row.
5. Result: **deleted entity appears active**.

**Complex variant (deleted=true row returned as non-empty Optional)**

With a delete/recreate/delete cycle, the `entity_history` branch can also return a row with `deleted=true` (e.g., `[T1,T2) deleted=true`), which `findActiveByIdAndTimestamp` would have filtered out. Callers that do not re-check the `deleted` flag then treat the deleted entity as present.

**Why existing tests fail to catch this**

The tests at lines 366–382 call `persistEntityHistoryWithDeleted()` without a corresponding `entity` row, so `entity_cte` returns NULL and both branches return empty — the test passes but never exercises the real attack path: [5](#0-4) 

Additionally, both tests pass `entityHistory.getTimestampLower() - 1` as the timestamp, making `lower(T) <= T-1` false, so the history row is never reached even if the CTE did return an ID.

## Impact Explanation

`findActiveByEvmAddressOrAliasAndTimestamp` is called by `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)`: [6](#0-5) 

This feeds directly into `AliasesReadableKVState.readFromDataSource()`, which resolves `AccountID` for the EVM state and does **not** re-check the `deleted` flag on the returned entity: [7](#0-6) 

Concrete consequences:
- A deleted entity is resolved as active in historical `eth_call` / `eth_getBalance` / contract-call queries, returning stale or incorrect balances and state.
- A `deleted=true` `entity_history` row is returned as a non-empty `Optional`, causing callers that do not re-check the `deleted` flag to treat the entity as present.
- Mirror node exports incorrect historical entity state, undermining the integrity guarantees of the mirror node API.

## Likelihood Explanation

No privilege is required. Any user of the public JSON-RPC endpoint can issue an `eth_call` or `eth_getBalance` with an arbitrary `blockNumber` (which maps to a `blockTimestamp`). The attacker only needs to know the EVM address or alias of a previously deleted account (publicly visible on-chain) and the block number at which the deletion occurred (also publicly visible). Entity deletion is a normal Hedera operation (account expiry, explicit deletion). The attack is fully repeatable and deterministic.

## Recommendation

Add `and eh.deleted is not true` to the `entity_history` branch in both affected queries, mirroring the pattern already used in `findActiveByIdAndTimestamp`:

```sql
-- findActiveByEvmAddressOrAliasAndTimestamp (and findActiveByEvmAddressAndTimestamp)
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

Additionally, fix the existing tests to include a corresponding `entity` row (so `entity_cte` returns a non-NULL ID) and use `timestampLower` or `timestampLower + 1` (not `timestampLower - 1`) so the history branch is actually exercised.

## Proof of Concept

**Database state:**
```sql
INSERT INTO entity (id, evm_address, created_timestamp, timestamp_range, deleted)
VALUES (1, '\xdeadbeef...', 1000, '[2000,)', true);

INSERT INTO entity_history (id, evm_address, timestamp_range, deleted)
VALUES (1, '\xdeadbeef...', '[1000,2000)', false);
```

**Query (blockTimestamp = 2000):**
```sql
with entity_cte as (
    select id from entity
    where evm_address = '\xdeadbeef...' and created_timestamp <= 2000
    order by created_timestamp desc limit 1
)
(select * from entity e where e.deleted is not true and e.id = (select id from entity_cte))
union all
(select * from entity_history eh where lower(eh.timestamp_range) <= 2000
 and eh.id = (select id from entity_cte)
 order by lower(eh.timestamp_range) desc limit 1)
order by timestamp_range desc limit 1;
```

**Expected result:** empty (entity is deleted at T=2000).
**Actual result:** returns the `[1000,2000) deleted=false` row — the deleted entity appears active.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L73-81)
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L136-155)
```java
    @Query(value = """
                    (
                        select *
                        from entity
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                    )
                    union all
                    (
                        select *
                        from entity_history
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                        order by lower(timestamp_range) desc
                        limit 1
                    )
                    order by timestamp_range desc
                    limit 1
                    """, nativeQuery = true)
    Optional<Entity> findActiveByIdAndTimestamp(long id, long blockTimestamp);
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/EntityRepositoryTest.java (L366-382)
```java
    @Test
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/AliasesReadableKVState.java (L57-68)
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
    }
```
