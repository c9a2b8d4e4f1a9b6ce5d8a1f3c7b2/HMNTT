Audit Report

## Title
Missing `lower(timestamp_range) <= blockTimestamp` Guard in `entity` Branch of `findActiveByEvmAddressOrAliasAndTimestamp()`

## Summary
The `entity` branch of the UNION query in `findActiveByEvmAddressOrAliasAndTimestamp()` omits the `lower(timestamp_range) <= ?2` predicate that is correctly present in the equivalent `findActiveByIdAndTimestamp()` query. Because the `entity` table holds the live state with an open-ended `timestamp_range = [T_last_update, ∞)`, the final `ORDER BY timestamp_range DESC LIMIT 1` will always prefer the current row over a correctly-bounded `entity_history` row when a historical timestamp is queried. The same defect is also present in `findActiveByEvmAddressAndTimestamp()`.

## Finding Description

**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`

The `entity` branch in `findActiveByEvmAddressOrAliasAndTimestamp()` (lines 103–108) has no timestamp guard:

```sql
select *
from entity e
where e.deleted is not true
  and e.id = (select id from entity_cte)
``` [1](#0-0) 

Compare with `findActiveByIdAndTimestamp()` (line 140), which correctly includes the guard:

```sql
select *
from entity
where id = ?1 and lower(timestamp_range) <= ?2
and deleted is not true
``` [2](#0-1) 

The same missing guard exists in `findActiveByEvmAddressAndTimestamp()` at lines 67–72. [3](#0-2) 

**Root cause:** The `entity_cte` uses `created_timestamp <= ?2` to confirm the entity existed at the queried block, but this says nothing about whether the *current* row's `timestamp_range` lower bound is ≤ `?2`. When an entity is updated after the queried timestamp, the current row's `timestamp_range = [T_update, ∞)` has a lower bound greater than the queried timestamp, yet it is still returned by the `entity` branch with no filtering. [4](#0-3) 

**Test gap:** The tests at lines 384–403 only cover the case where `blockTimestamp < entityHistory.getTimestampLower() - 1`, meaning `entity_cte` returns nothing and the result is empty. There is no test for the case where `created_timestamp ≤ blockTimestamp < lower(entity.timestamp_range)`. [5](#0-4) 

## Impact Explanation
Any historical `eth_call`, `eth_getBalance`, contract-code lookup, or alias resolution routed through `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` (line 48) will silently return the **current** entity state instead of the state at the requested block. [6](#0-5) 

This means post-update balances, changed keys, new contract bytecode, or updated memo fields are exposed to callers who are querying a past block. Protocols relying on historical state proofs (dispute resolution, snapshot-based governance, audit trails) receive incorrect data.

## Likelihood Explanation
No privilege is required. Any caller who can issue a JSON-RPC call with a block number parameter can trigger this path. The attacker only needs to know that an entity was updated after the target block — information publicly visible on the mirror node's REST API. The bug is deterministic and fully repeatable.

## Recommendation
Add `and lower(e.timestamp_range) <= ?2` to the `entity` branch in both affected queries:

**`findActiveByEvmAddressOrAliasAndTimestamp()`** (lines 103–108):
```sql
select *
from entity e
where e.deleted is not true
  and lower(e.timestamp_range) <= ?2          -- ADD THIS
  and e.id = (select id from entity_cte)
```

**`findActiveByEvmAddressAndTimestamp()`** (lines 67–72):
```sql
select *
from entity e
where e.deleted is not true
  and lower(e.timestamp_range) <= ?2          -- ADD THIS
  and e.id = (select id from entity_cte)
```

Add a test case covering the scenario: entity created at T1, updated at T3, queried at T2 where T1 ≤ T2 < T3 — the result must be the `entity_history` row, not the current `entity` row.

## Proof of Concept

1. Entity `E` is created at `T1`. `entity` table: `timestamp_range = [T1, ∞)`.
2. At `T3 > T1`, entity `E` is updated (e.g., balance changes). `entity` table now: `timestamp_range = [T3, ∞)`. `entity_history` gains row: `timestamp_range = [T1, T3)`.
3. Caller issues `eth_getBalance` (or `eth_call`) with `blockTimestamp = T2` where `T1 ≤ T2 < T3`.
4. `entity_cte` resolves the ID: `created_timestamp (T1) ≤ T2` — passes.
5. `entity` branch returns the current row (`timestamp_range = [T3, ∞)`) — **no guard prevents this**.
6. `entity_history` branch returns the correct row (`timestamp_range = [T1, T3)`) because `lower([T1,T3)) = T1 ≤ T2`.
7. `ORDER BY timestamp_range DESC LIMIT 1`: PostgreSQL orders ranges by lower bound; `T3 > T1`, so `[T3, ∞)` sorts above `[T1, T3)`.
8. The caller receives the **post-T3 state** for a query that should reflect the **T2 state**. [7](#0-6)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L67-72)
```java
            (
                select *
                from entity e
                where e.deleted is not true
                and e.id = (select id from entity_cte)
            )
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L95-121)
```java
    @Query(value = """
            with entity_cte as (
                select id
                from entity
                where created_timestamp <= ?2 and (evm_address = ?1 or alias = ?1)
                order by created_timestamp desc
                limit 1
            )
            (
                select *
                from entity e
                where e.deleted is not true
                and e.id = (select id from entity_cte)
            )
            union all
            (
                select *
                from entity_history eh
                where lower(eh.timestamp_range) <= ?2
                and eh.id = (select id from entity_cte)
                order by lower(eh.timestamp_range) desc
                limit 1
            )
            order by timestamp_range desc
            limit 1
            """, nativeQuery = true)
    Optional<Entity> findActiveByEvmAddressOrAliasAndTimestamp(byte[] alias, long blockTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L138-142)
```java
                        select *
                        from entity
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                    )
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/EntityRepositoryTest.java (L384-403)
```java
    @Test
    void findHistoricalEntityByEvmAddressOrAliasAndTimestampRangeGreaterThanBlockTimestampAndDeletedIsFalseWithAlias() {
        final var entityHistory = persistEntityHistory();
        final var entity = persistEntityWithId(entityHistory.getId());

        assertThat(entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(
                        entity.getAlias(), entityHistory.getTimestampLower() - 1))
                .isEmpty();
    }

    @Test
    void
            findHistoricalEntityByEvmAddressOrAliasAndTimestampRangeGreaterThanBlockTimestampAndDeletedIsFalseWithEvmAddress() {
        final var entityHistory = persistEntityHistory();
        final var entity = persistEntityWithId(entityHistory.getId());

        assertThat(entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(
                        entity.getEvmAddress(), entityHistory.getTimestampLower() - 1))
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
