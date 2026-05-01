### Title
Ghost Entity Resurrection: Deleted Entity Returned as Active via Stale History Record in `findActiveByEvmAddressAndTimestamp`

### Summary
The `entity_history` branch of the UNION ALL in `findActiveByEvmAddressAndTimestamp` only checks `lower(timestamp_range) <= blockTimestamp` but never verifies that `blockTimestamp` falls within the history record's closed upper bound. When a user supplies a `blockTimestamp` after an entity's deletion timestamp, the query returns the entity's pre-deletion history record (with `deleted=false`) as if the entity were still active, even though it was deleted before the queried timestamp.

### Finding Description

**File:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 59–85

**Data model (confirmed by `SqlEntityListenerTest.onEntityHistory`):**
When entity A (id=100, evm_address=X) is created at T1 and deleted at T2:
- `entity` table: id=100, deleted=**true**, timestamp_range=`[T2, ∞)`
- `entity_history` table: id=100, deleted=**false**, timestamp_range=`[T1, T2)` ← pre-deletion snapshot

**Query trace with `blockTimestamp = T_query` where `T1 < T2 < T_query < T3` (T3 = re-creation time):**

**CTE (lines 60–66):**
```sql
select id from entity
where evm_address = ?1 and created_timestamp <= ?2   -- T1 <= T_query ✓
order by created_timestamp desc limit 1
```
Returns id=100 (entity A, the deleted entity). Entity B (id=200, created at T3) is excluded because T3 > T_query.

**First UNION branch (lines 68–72):**
```sql
select * from entity e
where e.deleted is not true and e.id = 100
```
Entity A has `deleted=true` → **returns nothing**.

**Second UNION branch (lines 74–81):**
```sql
select * from entity_history eh
where lower(eh.timestamp_range) <= ?2   -- lower([T1,T2)) = T1 <= T_query ✓
and eh.id = 100
order by lower(eh.timestamp_range) desc limit 1
```
Returns the pre-deletion snapshot: id=100, timestamp_range=`[T1, T2)`, **deleted=false**.

**Final result:** The pre-deletion record (deleted=false) is returned. At T_query the entity was actually deleted at T2, but the query presents it as active.

**Root cause:** The `entity_history` branch checks only `lower(timestamp_range) <= blockTimestamp` (line 77) but never checks `blockTimestamp < upper(timestamp_range)`. A history record with range `[T1, T2)` is valid only for timestamps in `[T1, T2)`. When T_query ≥ T2, the record is expired but still matched.

**Failed assumption:** The query assumes that the most recent history record with `lower ≤ blockTimestamp` is the correct state at that timestamp. This is false when the entity was deleted (upper bound closed) before blockTimestamp.

**Existing check insufficiency:** The `deleted is not true` guard exists only on the live `entity` branch (line 70). The `entity_history` branch has no equivalent guard and no upper-bound range check.

### Impact Explanation
Any unprivileged caller of `eth_call` (or equivalent historical JSON-RPC) with a block number corresponding to a timestamp between an entity's deletion and re-creation receives incorrect state: a deleted contract or account is returned as active (deleted=false). This causes the EVM simulation layer (`CommonEntityAccessor.getEntityByEvmAddressTimestamp`, line 69) to treat a non-existent entity as live, producing incorrect execution results — e.g., calls to a deleted contract succeed, balance/nonce/code lookups return stale data, and existence checks return true when they should return false.

### Likelihood Explanation
Any unprivileged user can trigger this with a standard `eth_call` at a historical block. No special credentials, keys, or on-chain transactions are required. The attacker only needs to know (or enumerate) an EVM address that was deleted at some point — this is publicly observable on-chain. The window between deletion and re-creation can be arbitrarily long (or permanent if the address is never re-created), making the exploit reliably repeatable.

### Recommendation
Add an upper-bound check to the `entity_history` branch so that only records whose range contains `blockTimestamp` are matched:

```sql
(
    select *
    from entity_history eh
    where lower(eh.timestamp_range) <= ?2
      and (upper(eh.timestamp_range) > ?2 or upper(eh.timestamp_range) is null)
      and eh.id = (select id from entity_cte)
    order by lower(eh.timestamp_range) desc
    limit 1
)
```

Or equivalently using the PostgreSQL range containment operator:
```sql
where eh.timestamp_range @> ?2::bigint
```

The same fix must be applied to `findActiveByEvmAddressOrAliasAndTimestamp` (lines 95–121), which has the identical structural defect.

### Proof of Concept

**Preconditions:**
1. Entity A: evm_address=`0xABCD`, id=100, created_timestamp=1000, deleted at timestamp=2000 → `entity` row: deleted=true, timestamp_range=`[2000,∞)`; `entity_history` row: deleted=false, timestamp_range=`[1000,2000)`
2. Entity B: evm_address=`0xABCD`, id=200, created_timestamp=3000 (not yet created at query time)

**Trigger:**
```
eth_call { to: 0xABCD, ... } at block whose consensus_timestamp = 2500
```
This calls `findActiveByEvmAddressAndTimestamp(0xABCD, 2500)`.

**Expected result:** `Optional.empty()` — entity was deleted at T=2000, no entity exists at T=2500.

**Actual result:** Returns entity_history row for id=100 with `deleted=false`, `timestamp_range=[1000,2000)` — entity appears active.

**Verification SQL:**
```sql
-- Setup
INSERT INTO entity VALUES (100, '0xABCD', 1000, true,  '[2000,)'::int8range, ...);
INSERT INTO entity_history VALUES (100, '0xABCD', 1000, false, '[1000,2000)'::int8range, ...);

-- Trigger the buggy query with blockTimestamp=2500
WITH entity_cte AS (
  SELECT id FROM entity WHERE evm_address = '0xABCD' AND created_timestamp <= 2500
  ORDER BY created_timestamp DESC LIMIT 1
)
SELECT * FROM entity e WHERE e.deleted IS NOT TRUE AND e.id = (SELECT id FROM entity_cte)
UNION ALL
SELECT * FROM entity_history eh
WHERE lower(eh.timestamp_range) <= 2500 AND eh.id = (SELECT id FROM entity_cte)
ORDER BY timestamp_range DESC LIMIT 1;
-- Returns: id=100, deleted=false  ← INCORRECT
```