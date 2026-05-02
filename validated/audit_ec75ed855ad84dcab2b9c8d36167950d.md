The code confirms the vulnerability. Here is the audit report:

---

Audit Report

## Title
Missing `deleted is not true` Filter in `entity_history` Branch of `findActiveByEvmAddressAndTimestamp` and `findActiveByEvmAddressOrAliasAndTimestamp`

## Summary
The SQL queries `findActiveByEvmAddressAndTimestamp` and `findActiveByEvmAddressOrAliasAndTimestamp` in `EntityRepository.java` apply a `deleted is not true` guard only to the `entity` table branch. The `entity_history` branch is unguarded. For an entity that has undergone a create → delete → re-create lifecycle, supplying a `blockTimestamp` equal to the nanosecond of the first deletion causes the deleted history row to be selected and returned as an active entity.

## Finding Description

**Exact location:**
`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`

`findActiveByEvmAddressAndTimestamp` (lines 59–85):
- `entity` branch (lines 68–72): correctly has `e.deleted is not true`
- `entity_history` branch (lines 74–81): only filters `lower(eh.timestamp_range) <= ?2` — **no deleted guard** [1](#0-0) 

`findActiveByEvmAddressOrAliasAndTimestamp` (lines 95–121): identical omission in its `entity_history` branch (lines 110–117). [2](#0-1) 

**Contrast with `findActiveByIdAndTimestamp`** (lines 136–155), which correctly applies `and deleted is not true` in **both** branches: [3](#0-2) 

**Root cause:** `entity_history` stores every historical snapshot including the deletion snapshot (`deleted = true`). The missing filter allows the deletion snapshot to be selected and returned.

**Exploit flow** (entity lifecycle: create at T1, delete at T2, re-create at T3):

| Time | `entity` | `entity_history` |
|------|----------|-----------------|
| T1 | `{deleted=false, ts=[T1,∞)}` | — |
| T2 (delete) | `{deleted=true, ts=[T2,∞)}` | `{deleted=false, ts=[T1,T2)}` |
| T3 (re-create) | `{deleted=false, ts=[T3,∞)}` | + `{deleted=true, ts=[T2,T3)}` |

Attacker calls `eth_call` with `blockTimestamp = T2`:
1. `entity_cte` resolves the entity ID (`created_timestamp = T1 ≤ T2`).
2. `entity` branch: current row has `deleted=true` → filtered out.
3. `entity_history` branch: candidates with `lower(ts) ≤ T2`:
   - `{deleted=false, ts=[T1,T2)}` (lower = T1)
   - `{deleted=true, ts=[T2,T3)}` (lower = T2 ≤ T2) ← **no deleted guard, passes**
   - `ORDER BY lower(ts) DESC LIMIT 1` picks `{deleted=true, ts=[T2,T3)}`.
4. Outer `ORDER BY timestamp_range DESC LIMIT 1` returns the deleted row.
5. `CommonEntityAccessor.getEntityByEvmAddressTimestamp` (lines 80–84) returns this as a non-empty `Optional<Entity>` without inspecting `deleted`. [4](#0-3) 

**Why existing tests fail to catch this:** The test `findHistoricalEntityByEvmAddressAndTimestampRangeAndDeletedTrueCall` uses `getTimestampLower() - 1` as the `blockTimestamp`, which is strictly before the deletion record's lower bound. The `entity_history` branch therefore never selects the deleted row in that test. No test covers `blockTimestamp >= lower(deletion_row_timestamp_range)` paired with a matching `entity` row — the exact condition required for exploitation.

## Impact Explanation
During historical `eth_call` / `eth_estimateGas` queries, a deleted account is returned as active at the nanosecond of its deletion. The EVM layer receives a non-null entity and treats the address as an existing, active account. This falsifies `EXTCODESIZE`, `BALANCE`, and `CALL` opcode results for that address at that timestamp. Contracts relying on historical state proofs, audit trails, or replay-based verification logic receive incorrect data. The same flaw exists in `findActiveByEvmAddressOrAliasAndTimestamp`, widening the attack surface to alias-addressed lookups. [5](#0-4) 

## Likelihood Explanation
No privilege is required. Any caller of the public JSON-RPC `eth_call` endpoint can supply an arbitrary `blockNumber` (mapped to `blockTimestamp`). The deletion and re-creation timestamps of any account are publicly visible via the mirror node REST API. The delete + re-create lifecycle occurs naturally for recycled contract addresses. The attacker needs only the EVM address and the nanosecond-precision deletion timestamp, both freely available.

## Recommendation
Add `and eh.deleted is not true` to the `entity_history` branch of both affected queries, mirroring the fix already present in `findActiveByIdAndTimestamp`:

```sql
-- findActiveByEvmAddressAndTimestamp, entity_history branch
select *
from entity_history eh
where lower(eh.timestamp_range) <= ?2
and eh.deleted is not true          -- ADD THIS
and eh.id = (select id from entity_cte)
order by lower(eh.timestamp_range) desc
limit 1
```

Apply the same fix to the `entity_history` branch of `findActiveByEvmAddressOrAliasAndTimestamp`.

## Proof of Concept
1. Insert entity with `evm_address = X`, `created_timestamp = T1`, `deleted = false` into `entity`.
2. Simulate deletion at T2: move current row to `entity_history` as `{deleted=false, ts=[T1,T2)}`, update `entity` to `{deleted=true, ts=[T2,∞)}`.
3. Simulate re-creation at T3: move current row to `entity_history` as `{deleted=true, ts=[T2,T3)}`, insert new `entity` row `{deleted=false, ts=[T3,∞)}`.
4. Call `entityRepository.findActiveByEvmAddressAndTimestamp(X, T2)`.
5. **Expected:** `Optional.empty()` (entity was deleted at T2).
6. **Actual:** Returns `Optional` containing the row `{deleted=true, ts=[T2,T3)}` — a deleted entity returned as active. [6](#0-5)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L59-85)
```java
    @Query(value = """
            with entity_cte as (
                select id
                from entity
                where evm_address = ?1 and created_timestamp <= ?2
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
    Optional<Entity> findActiveByEvmAddressAndTimestamp(byte[] evmAddress, long blockTimestamp);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L80-84)
```java
    private Optional<Entity> getEntityByEvmAddressTimestamp(byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```
