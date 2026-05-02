### Title
Missing Timestamp Bound on Entity Branch in `findActiveByEvmAddressAndTimestamp` Returns Current State for Historical Queries

### Summary
The entity branch of `findActiveByEvmAddressAndTimestamp` omits the `lower(e.timestamp_range) <= ?2` predicate that is correctly present in the sibling method `findActiveByIdAndTimestamp`. For any entity with `deleted IS NULL` (the default for entities never explicitly deleted) that has been updated after the queried block timestamp, the `ORDER BY timestamp_range DESC LIMIT 1` tie-break always selects the current entity-table row over the correct historical entity_history row. Any unprivileged caller supplying a historical block number receives the entity's current state instead of its state at that block, silently misrepresenting on-chain history.

### Finding Description

**Exact code location:**
`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, `findActiveByEvmAddressAndTimestamp`, lines 67–72 (entity branch):

```sql
(
    select *
    from entity e
    where e.deleted is not true          -- ← NULL treated as active ✓
    and e.id = (select id from entity_cte)
    -- ← MISSING: lower(e.timestamp_range) <= ?2
)
```

Compare with `findActiveByIdAndTimestamp`, lines 137–142, which correctly includes the bound:

```sql
select *
from entity
where id = ?1 and lower(timestamp_range) <= ?2   -- ← present here
and deleted is not true
```

**Root cause / failed assumption:**
The CTE (lines 60–66) only guarantees `created_timestamp <= ?2`, i.e., the entity existed at some point before the queried timestamp. It does **not** guarantee that the entity's *current* row in the `entity` table was valid at `?2`. When an entity is updated, the old state is moved to `entity_history` with a closed range `[T0, T1)`, and the new state stays in `entity` with an open range `[T1, ∞)`. If `T1 > blockTimestamp`, the entity branch still returns the `[T1, ∞)` row because there is no `lower(e.timestamp_range) <= ?2` guard.

**Exploit flow (step-by-step):**

| Step | Detail |
|------|--------|
| Setup | Entity E (evm_address A) created at T0, updated at T1 (T1 > T0). `entity` table: `timestamp_range=[T1,∞)`, `deleted=NULL`. `entity_history`: `timestamp_range=[T0,T1)`. |
| Query | Attacker calls any web3 endpoint (e.g., `eth_getCode`, `eth_call`) with block number mapping to timestamp T0.5 where T0 < T0.5 < T1. |
| CTE | `created_timestamp=T0 ≤ T0.5` → entity ID resolved. |
| Entity branch | `deleted IS NULL` passes `deleted is not true`; no timestamp guard → returns T1-state row. |
| History branch | `lower([T0,T1))=T0 ≤ T0.5` → returns T0-state row. |
| Final ORDER BY | `[T1,∞) > [T0,T1)` in PostgreSQL range ordering → entity-table row wins. |
| Result | T1 (current) state returned for a T0.5 historical query — **incorrect**. |

**Why existing checks are insufficient:**
- The CTE's `created_timestamp <= ?2` only proves the entity existed; it does not bound the *current* row's validity window.
- `deleted is not true` correctly treats `NULL` as active for present-state queries but is irrelevant to the timestamp-ordering problem.
- The `entity_history` branch correctly applies `lower(eh.timestamp_range) <= ?2`, but the entity branch does not, so the entity-table row always wins the `ORDER BY` when `T1 > blockTimestamp`.
- The same structural defect exists in `findActiveByEvmAddressOrAliasAndTimestamp` (lines 103–108), which has an identical entity branch without the timestamp predicate.

### Impact Explanation
Any historical EVM query resolved via an EVM address (rather than a numeric entity ID) returns the entity's current on-chain state regardless of the requested block. This means:
- Contract bytecode, balance, key material, and other fields reflect the *present* state, not the state at the queried block.
- An entity that was deleted at block B but later re-created (or whose `deleted` flag was reset) will appear active when queried at any block between its creation and deletion.
- Audit tools, block explorers, and smart-contract replay engines that rely on the mirror node's historical EVM API receive silently corrupted data, undermining the integrity of Hashgraph history.

Severity: **Medium** — read-only data-integrity corruption; no direct fund loss, but historical correctness is a core guarantee of the mirror node.

### Likelihood Explanation
- **No privilege required.** Any caller of the public web3 JSON-RPC API (`eth_call`, `eth_getCode`, `eth_getBalance`, etc.) with a `blockNumber` parameter triggers this path via `CommonEntityAccessor.getEntityByEvmAddressTimestamp` → `findActiveByEvmAddressAndTimestamp`.
- **Affects all updated entities.** Every entity that has ever been updated (i.e., has at least one `entity_history` row with a lower `timestamp_range` lower-bound than the current `entity` row) is vulnerable.
- **Trivially repeatable.** The attacker only needs a known EVM address and any historical block number predating the entity's last update.

### Recommendation
Add `lower(e.timestamp_range) <= ?2` to the entity branch of both affected queries, mirroring `findActiveByIdAndTimestamp`:

```sql
-- findActiveByEvmAddressAndTimestamp, entity branch (fix)
select *
from entity e
where e.deleted is not true
  and lower(e.timestamp_range) <= ?2          -- ADD THIS
  and e.id = (select id from entity_cte)
```

Apply the identical fix to `findActiveByEvmAddressOrAliasAndTimestamp` (lines 103–108). Add a regression test that persists an entity at T0, updates it at T1, and asserts that querying at T0.5 returns the T0 (history) state, not the T1 (current) state.

### Proof of Concept

**Preconditions:**
1. Entity E with EVM address `A` exists in the mirror node database.
2. E has been updated at least once: `entity_history` contains a row with `timestamp_range=[T0, T1)` and `entity` contains a row with `timestamp_range=[T1, ∞)`, `deleted=NULL`.

**Steps:**
```
1. Determine T0 and T1 from the database:
   SELECT lower(timestamp_range) FROM entity_history WHERE evm_address = A;  -- T0
   SELECT lower(timestamp_range) FROM entity WHERE evm_address = A;           -- T1

2. Choose blockTimestamp = T0 + 1  (i.e., T0 < blockTimestamp < T1).

3. Call:
   curl -X POST <mirror-node-web3-url> \
     -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["<A>","<block_at_T0+1>"],"id":1}'

4. Observe: response returns the bytecode/state corresponding to T1 (current state).

5. Confirm: call the same endpoint with block_at_T1+1 (a block after the update).
   Both responses are identical, proving the historical query is not actually historical.

6. For comparison, call eth_getCode using the numeric entity ID path (which routes through
   findActiveByIdAndTimestamp) at the same historical block — it correctly returns the T0 state.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L103-108)
```java
            (
                select *
                from entity e
                where e.deleted is not true
                and e.id = (select id from entity_cte)
            )
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L137-142)
```java
                    (
                        select *
                        from entity
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                    )
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L80-84)
```java
    private Optional<Entity> getEntityByEvmAddressTimestamp(byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```
