After verifying the exact code at every cited location, the vulnerability is confirmed. Here is the full audit report.

---

Audit Report

## Title
Historical Entity Resurrection via Missing Upper-Bound and Deleted-Flag Checks in `findActiveByEvmAddressAndTimestamp` and `findActiveByEvmAddressOrAliasAndTimestamp`

## Summary
The `entity_history` UNION branch in both `findActiveByEvmAddressAndTimestamp` and `findActiveByEvmAddressOrAliasAndTimestamp` applies only a lower-bound predicate (`lower(eh.timestamp_range) <= ?2`) but omits both `upper(eh.timestamp_range) > ?2` and `eh.deleted is not true`. As a result, when an account is deleted at time T2, the pre-deletion `entity_history` snapshot (`deleted=false`, `timestamp_range=[T1,T2)`) is returned for every `blockTimestamp >= T2`, making the deleted account appear alive to all historical EVM state queries that resolve by EVM address.

## Finding Description

**Affected methods and exact lines:**

`findActiveByEvmAddressAndTimestamp` — `entity_history` branch, lines 75–81: [1](#0-0) 

```sql
select *
from entity_history eh
where lower(eh.timestamp_range) <= ?2      -- only lower-bound checked
and eh.id = (select id from entity_cte)
order by lower(eh.timestamp_range) desc
limit 1
```

`findActiveByEvmAddressOrAliasAndTimestamp` — identical pattern, lines 110–116: [2](#0-1) 

**Two missing predicates:**
1. `upper(eh.timestamp_range) > ?2` — without this, records whose validity window has already closed are still eligible.
2. `eh.deleted is not true` — without this, no deletion-flag guard exists in the history branch.

**Contrast with `findActiveByIdAndTimestamp`** (lines 144–150), which does carry `and deleted is not true` in its `entity_history` branch: [3](#0-2) 

**Exploit flow — query at `blockTimestamp = T2+1` for an account deleted at T2:**

| Step | Branch | Result |
|---|---|---|
| CTE | `entity WHERE evm_address=0xABC AND created_timestamp <= T2+1` | Resolves entity id=X ✓ |
| Branch 1 | `entity WHERE deleted IS NOT TRUE AND id=X` | Empty — entity is deleted ✓ |
| Branch 2 | `entity_history WHERE lower([T1,T2)) <= T2+1 AND id=X` | Returns `(deleted=false, range=[T1,T2))` ✗ |
| Outer sort | `ORDER BY timestamp_range DESC LIMIT 1` | Picks the history record ✗ |

The outer `ORDER BY timestamp_range DESC LIMIT 1` selects the only available row — the pre-deletion snapshot — and returns it with `deleted=false`.

**No further deleted-flag check in the caller.** `CommonEntityAccessor.getEntityByEvmAddressTimestamp` (lines 80–83) passes the result directly to callers: [4](#0-3) 

**Why existing tests do not catch this:**

The closest test, `findHistoricalEntityByEvmAddressAndTimestampRangeAndDeletedTrueCall` (lines 126–132), creates only an `EntityHistory` row (no matching `entity` row) and queries at `getTimestampLower() - 1`: [5](#0-4) 

Because the CTE queries the `entity` table and finds nothing, the test passes vacuously. No test covers the critical scenario: a deleted `entity` row + a pre-deletion `entity_history` row + `blockTimestamp > upper(timestamp_range)`.

## Impact Explanation
Any historical EVM query that resolves an account by EVM address (e.g., `eth_call`, `eth_getBalance`, `EXTCODEHASH`, `AliasesReadableKVState`, `ContractBytecodeReadableKVState`) receives a non-empty `Optional<Entity>` with `deleted=false` for a deleted account. Downstream logic that gates on `Optional.isPresent()` or on the `deleted` flag will treat the account as live, corrupting historical balance reads, code-hash results, and any smart-contract simulation that references the deleted address at a post-deletion block number. This effectively rewrites on-chain history for every deleted account in the mirror node's database.

## Likelihood Explanation
Exploitation requires zero privileges. The attacker needs only: (a) the EVM address of any previously deleted account — all deletions are public on-chain — and (b) the ability to issue a standard JSON-RPC call (`eth_call`, `eth_getBalance`, etc.) with a `blockNumber` parameter pointing to any block after the deletion. Both are freely available to any JSON-RPC client. The attack is deterministic and repeatable for every deleted account in the mirror node's history.

## Recommendation
Add both missing predicates to the `entity_history` branch in **both** affected queries:

```sql
select *
from entity_history eh
where lower(eh.timestamp_range) <= ?2
  and upper(eh.timestamp_range) > ?2      -- ADD: upper-bound containment
  and eh.deleted is not true              -- ADD: deletion-flag guard
  and eh.id = (select id from entity_cte)
order by lower(eh.timestamp_range) desc
limit 1
```

Alternatively, use the range-containment operator: `eh.timestamp_range @> ?2::int8`, which implicitly enforces both bounds.

Add a regression test that:
1. Persists an `Entity` row with `deleted=true` and `timestamp_range=[T2,∞)`.
2. Persists an `EntityHistory` row for the same id with `deleted=false` and `timestamp_range=[T1,T2)`.
3. Asserts that `findActiveByEvmAddressAndTimestamp(evmAddress, T2+1)` returns empty.

## Proof of Concept

```sql
-- Setup
INSERT INTO entity (id, evm_address, deleted, timestamp_range, created_timestamp)
  VALUES (42, '\xDEADBEEF', true, '[200,)', 100);

INSERT INTO entity_history (id, evm_address, deleted, timestamp_range)
  VALUES (42, '\xDEADBEEF', false, '[100,200)');

-- Exploit: query at blockTimestamp = 300 (after deletion at 200)
-- Expected: empty result
-- Actual: returns the entity_history row with deleted=false
WITH entity_cte AS (
  SELECT id FROM entity
  WHERE evm_address = '\xDEADBEEF' AND created_timestamp <= 300
  ORDER BY created_timestamp DESC LIMIT 1
)
(SELECT * FROM entity e
 WHERE e.deleted IS NOT TRUE AND e.id = (SELECT id FROM entity_cte))
UNION ALL
(SELECT * FROM entity_history eh
 WHERE lower(eh.timestamp_range) <= 300          -- 100 <= 300: TRUE
   AND eh.id = (SELECT id FROM entity_cte)
 ORDER BY lower(eh.timestamp_range) DESC LIMIT 1)
ORDER BY timestamp_range DESC LIMIT 1;
-- Returns: (id=42, deleted=false, timestamp_range=[100,200)) ← WRONG
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L74-81)
```java
            (
                select *
                from entity_history eh
                where lower(eh.timestamp_range) <= ?2
                and eh.id = (select id from entity_cte)
                order by lower(eh.timestamp_range) desc
                limit 1
            )
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L109-116)
```java
            union all
            (
                select *
                from entity_history eh
                where lower(eh.timestamp_range) <= ?2
                and eh.id = (select id from entity_cte)
                order by lower(eh.timestamp_range) desc
                limit 1
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L80-84)
```java
    private Optional<Entity> getEntityByEvmAddressTimestamp(byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/EntityRepositoryTest.java (L126-132)
```java
    void findHistoricalEntityByEvmAddressAndTimestampRangeAndDeletedTrueCall() {
        final var entityHistory = persistEntityHistoryWithDeleted();

        assertThat(entityRepository.findActiveByEvmAddressAndTimestamp(
                        entityHistory.getEvmAddress(), entityHistory.getTimestampLower() - 1))
                .isEmpty();
    }
```
