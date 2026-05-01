### Title
Missing `lower(timestamp_range)` Guard in Entity Branch Causes Historical Query to Return Post-Modification State

### Summary
`findActiveByEvmAddressOrAliasAndTimestamp()` (and its sibling `findActiveByEvmAddressAndTimestamp()`) omit a `lower(e.timestamp_range) <= blockTimestamp` filter on the `entity` table branch of the UNION ALL. The `entity_cte` anchors on `created_timestamp` (the entity's original birth time, which never changes), so any `blockTimestamp ≥ created_timestamp` resolves the entity ID — but the first UNION branch then returns the *current* entity row unconditionally. Because the current row's `timestamp_range` lower bound is the *modification* time (T2 > T1), it always sorts higher than the `entity_history` row under `ORDER BY timestamp_range DESC LIMIT 1`, causing the post-modification state to be returned for any historical query in the window `[created_timestamp, lower(entity.timestamp_range))`. Under replication lag the `entity_history` branch returns nothing at all, making the incorrect current-state result the only candidate.

### Finding Description

**Exact code path** — `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 95–121:

```sql
with entity_cte as (
    select id
    from entity
    where created_timestamp <= ?2          -- (A) uses original creation time
      and (evm_address = ?1 or alias = ?1)
    order by created_timestamp desc
    limit 1
)
(
    select *
    from entity e
    where e.deleted is not true            -- (B) NO lower(timestamp_range) <= ?2 check
      and e.id = (select id from entity_cte)
)
union all
(
    select *
    from entity_history eh
    where lower(eh.timestamp_range) <= ?2  -- (C) correctly guarded
      and eh.id = (select id from entity_cte)
    order by lower(eh.timestamp_range) desc
    limit 1
)
order by timestamp_range desc
limit 1
```

**Root cause**: Guard (A) uses `created_timestamp`, which is the entity's immutable birth timestamp and does not change when the entity is modified. After a modification at T2, the `entity` row retains `created_timestamp = T1` but its `timestamp_range` becomes `[T2, ∞)`. Guard (B) is absent, so the current row is always included in the UNION regardless of `blockTimestamp`. Because `lower([T2,∞)) = T2 > T1 = lower([T1,T2))`, the `ORDER BY timestamp_range DESC` always selects the current row over the history row, returning the post-modification state for any `blockTimestamp` in `[T1, T2)`.

**Contrast with the correct pattern** used in `findActiveByIdAndTimestamp()` (lines 136–155):
```sql
select *
from entity
where id = ?1 and lower(timestamp_range) <= ?2   -- guard present
  and deleted is not true
```

**Replication-partition amplifier**: When `entity_history` rows for `[T1, T2)` have not yet replicated to the read replica, branch (C) returns nothing. The UNION then contains only the current entity row, and the incorrect post-modification state is returned with no competing candidate.

**Exploit flow**:
1. Entity E is created at consensus timestamp T1; `entity.created_timestamp = T1`, `entity.timestamp_range = [T1, ∞)`.
2. E is modified at T2 > T1; `entity.timestamp_range` becomes `[T2, ∞)`, old state moves to `entity_history` with `timestamp_range = [T1, T2)`.
3. Attacker issues a historical `eth_call` (or `eth_getBalance`, etc.) specifying a block whose consensus timestamp is T1 (or any value in `[T1, T2)`).
4. The web3 service calls `findActiveByEvmAddressOrAliasAndTimestamp(alias, T1)`.
5. `entity_cte` resolves the ID (T1 ≤ T1 ✓). Branch (B) returns the current entity `[T2, ∞)`. Branch (C) returns `entity_history [T1, T2)` (or nothing under replication lag). `ORDER BY timestamp_range DESC` picks `[T2, ∞)`.
6. The caller receives the post-modification entity state for a block that predates the modification.

### Impact Explanation
Any historical EVM simulation that resolves an account or contract by EVM address or alias receives incorrect entity state. Concretely: balance, nonce, contract bytecode pointer, key material, and deletion status as of the queried block may all be wrong. A contract that did not exist at the queried block (created after T1 but before T2 under a re-deploy scenario) could appear to exist; a contract that was deleted and re-created could appear with its post-recreation state. This breaks the correctness guarantee of `eth_call` at historical blocks, which is relied upon by block explorers, auditing tools, and DeFi protocols that replay historical transactions.

### Likelihood Explanation
No privilege is required. Any caller who can issue a JSON-RPC `eth_call` with a `blockNumber` parameter can trigger this. The attacker only needs to know the EVM address or alias of any entity that has ever been modified (a trivially public fact on a transparent ledger) and supply a block number that falls before the modification. The replication-lag variant requires a transient infrastructure condition (normal under high write load or failover), but the base logic bug fires unconditionally even on a fully-synced primary.

### Recommendation
Add `lower(e.timestamp_range) <= ?2` to the `entity` branch of both `findActiveByEvmAddressOrAliasAndTimestamp` and `findActiveByEvmAddressAndTimestamp`, mirroring the pattern already used in `findActiveByIdAndTimestamp`:

```sql
(
    select *
    from entity e
    where e.deleted is not true
      and lower(e.timestamp_range) <= ?2   -- add this guard
      and e.id = (select id from entity_cte)
)
```

This ensures the current-state row is only included when its validity window has already started at or before the queried block timestamp, making the UNION semantics consistent with `findActiveByIdAndTimestamp`.

### Proof of Concept

```
-- Setup
INSERT INTO entity (id, evm_address, created_timestamp, timestamp_range, deleted, ...)
  VALUES (1, '\xDEAD...', 1000, '[2000, infinity)', false, ...);
-- entity was created at T1=1000, last modified at T2=2000

INSERT INTO entity_history (id, evm_address, created_timestamp, timestamp_range, deleted, ...)
  VALUES (1, '\xDEAD...', 1000, '[1000, 2000)', false, ...);
-- historical state valid during [1000, 2000)

-- Attacker query: blockTimestamp = 1500 (between creation T1=1000 and modification T2=2000)
-- Expected: entity_history row with timestamp_range [1000,2000)
-- Actual:   entity row with timestamp_range [2000,∞)  ← post-modification state returned

-- Replication-lag variant: DELETE FROM entity_history WHERE id=1;
-- (simulates missing replica row)
-- Result: same incorrect entity row returned, with no competing candidate
``` [1](#0-0) [2](#0-1)

### Citations

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
