Audit Report

## Title
Ghost Entity Resurrection: Deleted Entity Returned as Active via Missing Upper-Bound Check in `findActiveByEvmAddressAndTimestamp`

## Summary
The `entity_history` branch of the `UNION ALL` in `findActiveByEvmAddressAndTimestamp` checks only `lower(timestamp_range) <= blockTimestamp` but never verifies `blockTimestamp < upper(timestamp_range)`. When a caller supplies a `blockTimestamp` after an entity's deletion, the query returns the pre-deletion history record (with `deleted=false`) as if the entity were still active, even though it was deleted before the queried timestamp.

## Finding Description

**File:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 59–85

The query is:

```sql
with entity_cte as (
    select id from entity
    where evm_address = ?1 and created_timestamp <= ?2
    order by created_timestamp desc limit 1
)
(
    select * from entity e
    where e.deleted is not true          -- ← deletion guard present here
    and e.id = (select id from entity_cte)
)
union all
(
    select * from entity_history eh
    where lower(eh.timestamp_range) <= ?2  -- ← only lower-bound check, NO upper-bound
    and eh.id = (select id from entity_cte)
    order by lower(eh.timestamp_range) desc limit 1
)
order by timestamp_range desc limit 1
```

**Data model when entity A (id=100, evm_address=X) is created at T1 and deleted at T2:**
- `entity` table: id=100, `deleted=true`, `timestamp_range=[T2, ∞)`
- `entity_history` table: id=100, `deleted=false`, `timestamp_range=[T1, T2)` ← pre-deletion snapshot

**Query trace with `blockTimestamp = T_query` where `T1 < T2 < T_query`:**

1. **CTE** — `created_timestamp <= T_query` → T1 ≤ T_query ✓ → returns id=100
2. **First UNION branch** — entity has `deleted=true` → filtered by `deleted is not true` → returns nothing
3. **Second UNION branch** — `lower([T1,T2)) = T1 ≤ T_query` ✓ → returns the pre-deletion snapshot: id=100, `deleted=false`, `timestamp_range=[T1,T2)`
4. **Final** — only the history record is in the result set → returned as the entity's state

**Root cause:** The `entity_history` branch (line 77) checks only `lower(eh.timestamp_range) <= ?2`. A history record with range `[T1, T2)` is valid only for timestamps in `[T1, T2)`. When `T_query ≥ T2`, the record is expired but still matched because the upper bound `T2` is never checked.

**Contrast with `findActiveByIdAndTimestamp`** (lines 136–155): that query adds `and deleted is not true` to the `entity_history` branch, but it also lacks the upper-bound check — meaning the same class of bug exists there for the pre-deletion snapshot (which has `deleted=false`). The evm-address variant is additionally missing even the `deleted is not true` guard on the history branch.

The same flaw is present in the sibling method `findActiveByEvmAddressOrAliasAndTimestamp` (lines 95–121), which has an identical `entity_history` branch structure.

No existing test covers the scenario where `blockTimestamp > upper(timestamp_range)` of the history record while the live `entity` row has `deleted=true`. The closest test (`findHistoricalEntityByEvmAddressAndTimestampRangeAndDeletedTrueCall`, line 126) only tests `blockTimestamp < lower(timestamp_range)`, which is a different condition.

## Impact Explanation
`CommonEntityAccessor.getEntityByEvmAddressTimestamp` (line 69 of `CommonEntityAccessor.java`) calls `findActiveByEvmAddressAndTimestamp` directly. When the query incorrectly returns a deleted entity as active (`deleted=false`), the EVM simulation layer treats the non-existent entity as live. Consequences include:

- `eth_call` at a historical block returns results as if a deleted contract still exists
- Balance, nonce, and bytecode lookups return stale pre-deletion data
- Contract existence checks return `true` when they should return `false`
- Any logic in a calling contract that branches on `EXTCODESIZE` or `EXTCODEHASH` of the deleted address receives incorrect values

## Likelihood Explanation
Any unprivileged caller of the JSON-RPC `eth_call` endpoint with a historical block number can trigger this. No credentials, keys, or special on-chain state are required. The attacker only needs to know an EVM address that was deleted at some point — this is publicly observable from chain history. The vulnerable window is the entire period from deletion to re-creation (which may be permanent), making the condition reliably and repeatably exploitable.

## Recommendation
Add an upper-bound check to the `entity_history` branch in both `findActiveByEvmAddressAndTimestamp` and `findActiveByEvmAddressOrAliasAndTimestamp`:

```sql
(
    select * from entity_history eh
    where lower(eh.timestamp_range) <= ?2
    and ?2 < upper(eh.timestamp_range)   -- ADD THIS
    and eh.id = (select id from entity_cte)
    order by lower(eh.timestamp_range) desc limit 1
)
```

Alternatively, use the PostgreSQL range containment operator:
```sql
where eh.timestamp_range @> ?2::int8
```

Also add `and eh.deleted is not true` to the `entity_history` branch (currently absent in the evm-address variants, unlike `findActiveByIdAndTimestamp`).

Add a regression test that sets up: (1) an `entity_history` record with `deleted=false` and `timestamp_range=[T1,T2)`, (2) an `entity` record with `deleted=true` and `timestamp_range=[T2,∞)`, and asserts that querying with `blockTimestamp = T2 + 1` returns empty.

## Proof of Concept

```
Setup:
  entity_history: id=100, evm_address=X, deleted=false, timestamp_range=[1000, 2000)
  entity:         id=100, evm_address=X, deleted=true,  timestamp_range=[2000, ∞)

Call:
  entityRepository.findActiveByEvmAddressAndTimestamp(X, 3000)

Expected: Optional.empty()   (entity was deleted at T=2000, query is at T=3000)
Actual:   Optional[id=100, deleted=false, timestamp_range=[1000,2000)]
          ← pre-deletion snapshot incorrectly returned as active
```