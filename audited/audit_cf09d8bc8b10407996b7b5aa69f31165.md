### Title
Missing `deleted is not true` Filter on `entity_history` Sub-query in `findActiveByEvmAddressOrAliasAndTimestamp`

### Summary
The SQL query in `findActiveByEvmAddressOrAliasAndTimestamp` omits a `deleted is not true` predicate on the `entity_history` branch of its UNION ALL, while the analogous `findActiveByIdAndTimestamp` method correctly includes it. As a result, a historical contract call submitted by any unprivileged user using a deleted entity's alias or EVM address with a post-deletion block timestamp will receive the entity's last pre-deletion state from `entity_history`, incorrectly treating the entity as alive.

### Finding Description

**Exact code location:**
`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, `findActiveByEvmAddressOrAliasAndTimestamp`, lines 95–121.

The `entity_history` branch (lines 109–116) reads:
```sql
(
    select *
    from entity_history eh
    where lower(eh.timestamp_range) <= ?2
    and eh.id = (select id from entity_cte)
    order by lower(eh.timestamp_range) desc
    limit 1
)
```
There is **no** `deleted is not true` predicate here.

Compare with `findActiveByIdAndTimestamp` (lines 144–150), which correctly has:
```sql
(
    select *
    from entity_history
    where id = ?1 and lower(timestamp_range) <= ?2
    and deleted is not true
    order by lower(timestamp_range) desc
    limit 1
)
```

**Root cause / failed assumption:**
The query assumes that the `entity` branch's `deleted is not true` guard (line 106) is sufficient to suppress deleted entities. It is not, because the UNION ALL means the `entity_history` branch is evaluated independently. When the current `entity` row has `deleted = true` (so the first branch returns zero rows), the `entity_history` branch still returns the most recent historical row — which may have `deleted = false` (the pre-deletion snapshot).

**Exploit flow:**

State setup (normal Hedera lifecycle):
- T1: Entity E created with `alias = A`. `entity` table: `{id=E, alias=A, deleted=false, timestamp_range=[T1,∞)}`.
- T2: Entity E updated. Old state archived to `entity_history`: `{id=E, alias=A, deleted=false, timestamp_range=[T1,T2)}`. `entity` table updated to `timestamp_range=[T2,∞)`.
- T3: Entity E deleted. Old state archived to `entity_history`: `{id=E, alias=A, deleted=false, timestamp_range=[T2,T3)}`. `entity` table: `{id=E, alias=A, deleted=true, timestamp_range=[T3,∞)}`.

Attacker submits a historical contract call with `alias=A`, `blockTimestamp=T4` where `T4 ≥ T3`:

1. **`entity_cte`**: `SELECT id FROM entity WHERE created_timestamp <= T4 AND (evm_address=A OR alias=A)` → finds `id=E` (no `deleted` filter here).
2. **`entity` branch**: `WHERE e.deleted is not true AND e.id=E` → returns **nothing** (entity is deleted).
3. **`entity_history` branch**: `WHERE lower(timestamp_range) <= T4 AND id=E ORDER BY lower(timestamp_range) DESC LIMIT 1` → returns `{id=E, alias=A, deleted=false, timestamp_range=[T2,T3)}`.
4. **UNION ALL + final ORDER/LIMIT**: returns the pre-deletion snapshot with `deleted=false`.

The caller (`CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)`, line 48) receives a non-empty `Optional<Entity>` for an entity that was deleted before the queried timestamp.

**Why existing checks are insufficient:**
- The `entity` branch guard (`deleted is not true`, line 106) only prevents the current-state row from being returned; it does not affect the `entity_history` branch.
- The existing test `findHistoricalEntityByEvmAddressOrAliasAndTimestampRangeAndDeletedTrueCallWithAlias` (test file lines 367–372) uses `entityHistory.getTimestampLower() - 1` — a timestamp *before* the history record — so `entity_cte` finds nothing and the test passes vacuously. No test covers the scenario where `entity` is deleted and `entity_history` holds a pre-deletion `deleted=false` row queried at a post-deletion timestamp.

### Impact Explanation
Any historical EVM contract call resolved via alias or EVM address against a deleted entity will see that entity as alive. This means:
- Deleted contracts/accounts appear to exist in historical simulations, returning stale code, balance, or storage.
- Mirror node historical exports driven by this path reflect incorrect entity state.
- Downstream consumers (indexers, auditors, dApps) relying on historical call results receive false data about entity lifecycle.

Severity: **Medium**. Data integrity of historical state is compromised; no direct fund loss, but incorrect state can mislead protocol-level decisions and audits.

### Likelihood Explanation
- **No privilege required.** The web3 JSON-RPC `eth_call` with a `blockNumber` parameter (historical call) is publicly accessible.
- **Precondition is common.** Deleted contracts/accounts are a normal part of Hedera's lifecycle (e.g., `CryptoDelete`, `ContractDelete`).
- **Trivially repeatable.** The attacker only needs the alias or EVM address of any previously deleted entity (obtainable from public mirror node REST APIs) and any block number after the deletion timestamp.

### Recommendation
Add `and eh.deleted is not true` to the `entity_history` branch of both `findActiveByEvmAddressOrAliasAndTimestamp` and the structurally identical `findActiveByEvmAddressAndTimestamp`, mirroring the pattern already used in `findActiveByIdAndTimestamp`:

```sql
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

Add a regression test that:
1. Persists an entity with alias/evm_address.
2. Persists a corresponding `entity_history` row with `deleted=false` and `timestamp_range=[T1,T2)`.
3. Sets the current `entity` row to `deleted=true` with `timestamp_range=[T2,∞)`.
4. Asserts that `findActiveByEvmAddressOrAliasAndTimestamp(alias, T3)` where `T3 ≥ T2` returns **empty**.

### Proof of Concept

```sql
-- Setup
INSERT INTO entity (id, alias, evm_address, deleted, created_timestamp, timestamp_range)
  VALUES (42, '\xDEAD', '\xBEEF', true, 1000, '[3000, )');

INSERT INTO entity_history (id, alias, evm_address, deleted, created_timestamp, timestamp_range)
  VALUES (42, '\xDEAD', '\xBEEF', false, 1000, '[1000, 3000)');

-- Attacker query: historical call at timestamp 5000 (after deletion at 3000)
-- Simulates findActiveByEvmAddressOrAliasAndTimestamp('\xDEAD', 5000)
WITH entity_cte AS (
    SELECT id FROM entity
    WHERE created_timestamp <= 5000
      AND (evm_address = '\xBEEF' OR alias = '\xDEAD')
    ORDER BY created_timestamp DESC LIMIT 1
)
(SELECT * FROM entity e
 WHERE e.deleted IS NOT TRUE AND e.id = (SELECT id FROM entity_cte))
UNION ALL
(SELECT * FROM entity_history eh
 WHERE lower(eh.timestamp_range) <= 5000
   AND eh.id = (SELECT id FROM entity_cte)
 ORDER BY lower(eh.timestamp_range) DESC LIMIT 1)
ORDER BY timestamp_range DESC LIMIT 1;

-- Result: returns entity_history row with deleted=false, timestamp_range=[1000,3000)
-- Expected: empty result set
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L144-151)
```java
                    (
                        select *
                        from entity_history
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                        order by lower(timestamp_range) desc
                        limit 1
                    )
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
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
