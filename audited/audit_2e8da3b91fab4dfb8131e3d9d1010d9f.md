### Title
Missing `deleted is not true` Filter in `entity_history` Branch of `findActiveByEvmAddressOrAliasAndTimestamp`

### Summary
The `findActiveByEvmAddressOrAliasAndTimestamp` query in `EntityRepository.java` applies a `deleted is not true` guard only to the `entity` table branch, not to the `entity_history` branch. When a user-controlled `blockTimestamp` falls at or after an entity's deletion timestamp, the `entity_history` branch returns the deletion record (which carries `deleted = true`) instead of returning an empty result. The sibling method `findActiveByIdAndTimestamp` correctly applies `deleted is not true` to both branches, making this an inconsistency that can be triggered by any unprivileged caller.

### Finding Description

**Exact code location:**
`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 95–121 (`findActiveByEvmAddressOrAliasAndTimestamp`) and lines 136–155 (`findActiveByIdAndTimestamp`).

**Root cause — asymmetric `deleted` filtering:**

`findActiveByEvmAddressOrAliasAndTimestamp` (lines 95–121):
```sql
-- entity branch: has the guard
select * from entity e
where e.deleted is not true
  and e.id = (select id from entity_cte)

union all

-- entity_history branch: NO guard
select * from entity_history eh
where lower(eh.timestamp_range) <= ?2
  and eh.id = (select id from entity_cte)
order by lower(eh.timestamp_range) desc
limit 1
```

`findActiveByIdAndTimestamp` (lines 136–155):
```sql
-- entity_history branch: guard IS present
select * from entity_history
where id = ?1 and lower(timestamp_range) <= ?2
  and deleted is not true          -- ← correct
order by lower(timestamp_range) desc
limit 1
``` [1](#0-0) [2](#0-1) 

**Exploit flow:**

1. Entity `E` is created at `T1`, deleted at `T2`. The `entity` table row has `deleted = true`; `entity_history` gains a row with `lower(timestamp_range) = T2` and `deleted = true`.
2. Attacker calls any RPC endpoint that resolves an account/contract by EVM address or alias with a historical block number whose consensus timestamp `T3 ≥ T2`.
3. `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` (line 48) calls `findActiveByEvmAddressOrAliasAndTimestamp(alias, T3)`.
4. `entity_cte` resolves the entity ID (no `deleted` filter there either).
5. The `entity` branch returns nothing (correctly filtered).
6. The `entity_history` branch returns the deletion record (`deleted = true`) because there is no `deleted is not true` predicate.
7. The `UNION ALL … ORDER BY timestamp_range DESC LIMIT 1` picks that record and returns it to the caller. [3](#0-2) 

**Why existing checks are insufficient:**

`CommonEntityAccessor.get()` returns the `Optional<Entity>` directly without inspecting the `deleted` field of the returned entity. Downstream consumers that call `get()` and receive a non-empty `Optional` assume the entity is active. [3](#0-2) 

### Impact Explanation
Any historical `eth_call`, `eth_getBalance`, or contract-resolution query that uses an EVM address or alias can be made to return a deleted entity's state (balance, bytecode, storage) for timestamps after the entity's deletion. This causes the mirror node to misrepresent a deleted account or contract as existing at a queried block, corrupting historical state views. Downstream logic that relies on the presence of a returned entity (rather than also checking `entity.isDeleted()`) will treat the deleted entity as live, potentially affecting token-association checks, contract-existence guards, and balance reads used in replayed historical transactions.

### Likelihood Explanation
The `blockTimestamp` is derived directly from the user-supplied block number in standard JSON-RPC calls (`eth_call` with a block parameter, `eth_getBalance`, etc.). No authentication or privilege is required. Any caller who knows (or can enumerate) a previously-deleted contract or account address can reproduce this deterministically and repeatedly.

### Recommendation
Add `and deleted is not true` to the `entity_history` branch of both `findActiveByEvmAddressOrAliasAndTimestamp` and `findActiveByEvmAddressAndTimestamp`, mirroring the pattern already used in `findActiveByIdAndTimestamp`:

```sql
(
    select *
    from entity_history eh
    where lower(eh.timestamp_range) <= ?2
      and eh.id = (select id from entity_cte)
      and eh.deleted is not true          -- add this line
    order by lower(eh.timestamp_range) desc
    limit 1
)
``` [1](#0-0) [4](#0-3) 

### Proof of Concept

**Preconditions:**
- Entity `E` with EVM address `0xABCD…` was created at consensus timestamp `T1` and deleted at `T2` (`T2 > T1`).
- Mirror node is running and exposes a JSON-RPC endpoint.

**Steps:**
1. Determine the block number `B` whose consensus timestamp `T3 ≥ T2` (any block after deletion).
2. Issue: `eth_getBalance("0xABCD…", hex(B))` or `eth_call({to: "0xABCD…"}, hex(B))`.
3. Internally, `CommonEntityAccessor.get(alias=0xABCD…, timestamp=T3)` calls `findActiveByEvmAddressOrAliasAndTimestamp`.
4. The `entity_history` branch returns the deletion record (no `deleted is not true` guard).
5. The caller receives a non-empty `Optional<Entity>` with `deleted = true` — the entity appears to exist at block `B`, after it was deleted.

**Expected result (correct):** Empty `Optional` — entity does not exist at block `B`.
**Actual result (buggy):** Non-empty `Optional<Entity>` with `deleted = true` returned to caller.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L75-84)
```java
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L109-120)
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
            order by timestamp_range desc
            limit 1
            """, nativeQuery = true)
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L143-154)
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
                    order by timestamp_range desc
                    limit 1
                    """, nativeQuery = true)
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```
