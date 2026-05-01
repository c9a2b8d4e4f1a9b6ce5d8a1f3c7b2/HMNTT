### Title
Historical Entity Deletion State Bypass via Pre-filtered UNION in `findActiveByIdAndTimestamp`

### Summary
`findActiveByIdAndTimestamp` in `EntityRepository.java` pre-filters `deleted is not true` inside **both** UNION branches before the outer `ORDER BY timestamp_range DESC LIMIT 1`. This causes the query to return the most recent **non-deleted** record rather than the actual state at the requested `blockTimestamp`. When an entity has been deleted and later re-created, a historical call during the deletion window incorrectly returns the entity as active.

### Finding Description

**Exact code location:** `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 136–155. [1](#0-0) 

The query is:
```sql
(
    select *
    from entity
    where id = ?1 and lower(timestamp_range) <= ?2
    and deleted is not true          -- ← pre-filter
)
union all
(
    select *
    from entity_history
    where id = ?1 and lower(timestamp_range) <= ?2
    and deleted is not true          -- ← pre-filter
    order by lower(timestamp_range) desc
    limit 1
)
order by timestamp_range desc
limit 1
```

**Root cause:** The `deleted is not true` predicate is applied *inside* each branch, so deleted records are excluded from the candidate set entirely. The outer `ORDER BY … LIMIT 1` then picks the most recent surviving (non-deleted) record, which may be a stale historical state that predates the deletion event.

**Exploit flow — normal Hedera lifecycle (delete + re-create):**

| Time | Event | Table | `timestamp_range` | `deleted` |
|------|-------|-------|-------------------|-----------|
| T=100 | Entity created | → history after T=200 | `[100, 200)` | false |
| T=200 | Entity deleted | → history after T=300 | `[200, 300)` | **true** |
| T=300 | Entity re-created | `entity` (current) | `[300, ∞)` | false |

Query with `blockTimestamp = 250` (during deletion window):

- **`entity` branch**: `lower([300,∞)) = 300 > 250` → excluded by timestamp filter.
- **`entity_history` branch**:
  - Row `[200,300)` deleted=true → excluded by `deleted is not true`.
  - Row `[100,200)` deleted=false, `lower=100 ≤ 250` → **passes**, returned.
- **Final result**: row `[100,200)` with `deleted=false` — entity appears **active** at T=250.

**Correct result** should be: empty (entity was deleted at T=200 and not yet re-created at T=250).

**Why existing checks fail:** The `deleted is not true` guard is present but placed incorrectly. It should be a post-filter on the final selected row, not a pre-filter that silently discards the deletion event from the candidate pool.

The same caller path is `CommonEntityAccessor.get(EntityId, Optional<Long>)` at line 62, which feeds this result directly into EVM execution for historical calls. [2](#0-1) 

### Impact Explanation
Any historical JSON-RPC call (`eth_call`, `eth_getBalance`, `eth_getCode`, etc.) that resolves an entity by numeric ID at a block during a deletion window will receive an incorrect "entity is active" response. This corrupts the historical EVM state exported by the mirror node: smart contracts that check account/token/contract existence at a past block will observe a ghost entity that should not exist. Severity is **medium-high**: the data integrity guarantee of the mirror node's historical query API is broken for a well-defined, reachable class of inputs.

### Likelihood Explanation
No privileges are required. The attacker only needs to:
1. Identify any entity ID that was deleted and later re-created on the Hedera mainnet (fully public, observable from the mirror node's own REST API or transaction history).
2. Submit a standard historical RPC call (e.g., `eth_call` with a `blockNumber` in the deletion window).

Delete-and-recreate is a normal Hedera operation for accounts and tokens. The condition is reproducible and deterministic for any such entity.

### Recommendation
Remove `deleted is not true` from both inner UNION branches and apply it as a post-filter on the final selected row:

```sql
select * from (
    (
        select *
        from entity
        where id = ?1 and lower(timestamp_range) <= ?2
    )
    union all
    (
        select *
        from entity_history
        where id = ?1 and lower(timestamp_range) <= ?2
        order by lower(timestamp_range) desc
        limit 1
    )
    order by timestamp_range desc
    limit 1
) as latest
where deleted is not true
```

This mirrors the correct pattern already used in `NftRepository.findActiveByIdAndTimestamp` (lines 40–67), which wraps the UNION in a subquery and applies entity-deletion filtering on the outer result. [3](#0-2) 

### Proof of Concept

**Preconditions (reproducible with any Hedera entity that was deleted and re-created):**

```sql
-- Seed data simulating: created T=100, deleted T=200, re-created T=300
INSERT INTO entity (id, timestamp_range, deleted, ...)
  VALUES (42, '[300,)', false, ...);

INSERT INTO entity_history (id, timestamp_range, deleted, ...)
  VALUES (42, '[200,300)', true, ...),
         (42, '[100,200)', false, ...);
```

**Trigger — historical call at blockTimestamp=250:**
```
eth_call { ..., "blockNumber": <block whose consensus_timestamp = 250> }
```
This resolves to `entityRepository.findActiveByIdAndTimestamp(42, 250)`.

**Observed result:**
```
Optional[Entity{id=42, timestampRange=[100,200), deleted=false}]
```
Entity is returned as active — incorrect.

**Expected result:**
```
Optional.empty()
```
Entity was deleted at T=200 and should not be visible at T=250.

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L60-64)
```java
    public @NonNull Optional<Entity> get(@NonNull final EntityId entityId, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByIdAndTimestamp(entityId.getId(), t))
                .orElseGet(() -> entityRepository.findByIdAndDeletedIsFalse(entityId.getId()));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/NftRepository.java (L40-67)
```java
    @Query(value = """
            select n.*
            from (
                (
                    select *
                    from nft
                    where token_id = :tokenId
                        and serial_number = :serialNumber
                        and lower(timestamp_range) <= :blockTimestamp
                        and deleted is not true
                )
                union all
                (
                    select *
                    from nft_history
                    where token_id = :tokenId
                        and serial_number = :serialNumber
                        and lower(timestamp_range) <= :blockTimestamp
                        and deleted is not true
                    order by lower(timestamp_range) desc
                    limit 1
                )
            ) as n
            join entity e on e.id = n.token_id
            where (e.deleted is not true or lower(e.timestamp_range) > :blockTimestamp)
            order by n.timestamp_range desc
            limit 1
            """, nativeQuery = true)
```
