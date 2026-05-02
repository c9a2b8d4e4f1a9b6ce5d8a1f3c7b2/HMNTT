### Title
Inconsistent Entity Visibility: `deleted = NULL` Entities Returned by Alias Lookup but Silently Dropped by EVM Address Lookup

### Summary
In `rest/service/entityService.js`, `entityFromAliasQuery` uses `coalesce(deleted, false) <> true` which correctly treats `NULL` as "not deleted" and returns the entity, while `entityFromEvmAddressQuery` uses bare `deleted <> true` which evaluates to SQL `NULL` (not `TRUE`) when `deleted IS NULL`, silently excluding the entity. Because the `entity.deleted` column is explicitly nullable by design (migration `V1.39.1` dropped the `NOT NULL` constraint to support upsert operations), entities with `deleted = NULL` are a normal, expected database state. An unprivileged external user can exploit this by querying the same entity via its alias versus its EVM address, receiving contradictory results from the mirror node.

### Finding Description

**Exact code locations:**

`entityFromAliasQuery` — [1](#0-0) 

```sql
where coalesce(deleted, false) <> true   -- NULL → false → false <> true → TRUE → entity returned
  and alias = $1
```

`entityFromEvmAddressQuery` — [2](#0-1) 

```sql
where deleted <> true                    -- NULL <> true → NULL → WHERE fails → entity silently dropped
  and evm_address = $1
```

These queries back `getAccountFromAlias()` (line 42) and `getEntityIdFromEvmAddress()` (line 90) respectively. [3](#0-2) 

**Root cause confirmed by schema migration:**

Migration `V1.39.1` explicitly dropped the `NOT NULL` constraint and default from `entity.deleted`: [4](#0-3) 

The comment reads: *"allow nullable on entity deleted as transaction cannot make this assumption on updates."* This means `deleted = NULL` is not a corrupt state — it is the normal state for entities that have been upserted without an explicit deletion event. The upsert generator confirms `coalesce(deleted, e_deleted, null)` can produce NULL. [5](#0-4) 

**Exploit flow:**

1. An entity exists in the `entity` table with `deleted = NULL`, a non-null `alias`, and a non-null `evm_address` (common for ECDSA secp256k1 accounts).
2. Attacker (or any user) queries the mirror node REST API using the entity's alias → `getAccountFromAlias()` → `entityFromAliasQuery` → `coalesce(NULL, false) <> true` = `TRUE` → **entity returned**.
3. Same user queries using the entity's EVM address → `getEntityIdFromEvmAddress()` → `entityFromEvmAddressQuery` → `NULL <> true` = `NULL` → **entity silently dropped**, `rows.length === 0` → `NotFoundError` or `null` returned. [6](#0-5) 
4. The `getEncodedId()` dispatcher routes to one path or the other based solely on input format, with no reconciliation. [7](#0-6) 

**Why existing checks fail:** There is no cross-check or fallback between the two paths. The alias path has the correct `coalesce` guard; the EVM address path does not. No test covers the `deleted = NULL` case for EVM address lookup.

### Impact Explanation

The mirror node is the authoritative read layer for Hedera network state. Inconsistent entity visibility depending on lookup path means:

- Downstream consumers (wallets, explorers, dApps) that resolve the same account by EVM address will see it as non-existent while alias-based resolvers see it as active.
- Any authorization or existence check performed via EVM address lookup will incorrectly report the entity as absent, potentially causing denial-of-service for valid accounts or allowing logic that assumes "entity not found" to proceed incorrectly.
- The inconsistency is silent — no error is logged, no warning is surfaced; `getEntityIdFromEvmAddress` simply returns `null` or throws `NotFoundError`.

Severity: **Medium**. Data integrity violation in the mirror node's core entity resolution, affecting all entities with `deleted = NULL` (a normal importer state).

### Likelihood Explanation

- **No privileges required.** Any user with knowledge of an account's alias and EVM address can trigger the inconsistency via standard public REST API calls.
- **Precondition is common.** Entities inserted via the upsert path without an explicit deletion event will have `deleted = NULL`. This is the designed behavior per migration V1.39.1.
- **Repeatable and deterministic.** The SQL behavior of `NULL <> true` is a fixed property of PostgreSQL's three-valued logic; the inconsistency will reproduce on every query for every affected entity.

### Recommendation

Replace the bare `deleted <> true` in `entityFromEvmAddressQuery` with the same `coalesce` pattern used in `entityFromAliasQuery`:

```js
static entityFromEvmAddressQuery = `select ${Entity.ID}
                                    from ${Entity.tableName}
                                    where coalesce(${Entity.DELETED}, false) <> true
                                      and ${Entity.EVM_ADDRESS} = $1`;
```

This aligns both queries' treatment of `NULL` as "not deleted," consistent with the system's semantic intent and the alias query's existing behavior. Add a test case for `deleted = NULL` entities in both lookup paths.

### Proof of Concept

```sql
-- 1. Insert entity with deleted = NULL (normal upsert state)
INSERT INTO entity (id, num, realm, shard, alias, evm_address, type, timestamp_range)
VALUES (1, 1, 0, 0, '\xdeadbeef', '\xabcdef1234567890abcdef1234567890abcdef12', 'ACCOUNT', '[0,)');
-- deleted column is NULL (not set)

-- 2. Alias lookup (entityFromAliasQuery) — returns the entity
SELECT id FROM entity
WHERE coalesce(deleted, false) <> true
  AND alias = '\xdeadbeef';
-- Result: 1 row returned ✓

-- 3. EVM address lookup (entityFromEvmAddressQuery) — silently drops it
SELECT id FROM entity
WHERE deleted <> true
  AND evm_address = '\xabcdef1234567890abcdef1234567890abcdef12';
-- Result: 0 rows returned (NULL <> true evaluates to NULL) ✗
```

REST API reproduction:
```
GET /api/v1/accounts/0.0.KGNABD5L3ZGSRVUCSPDR7TONZSRY3D5OMEBKQMVTD2AC6JL72HMQ
→ 200 OK (entity found via alias)

GET /api/v1/accounts/0xabcdef1234567890abcdef1234567890abcdef12
→ 404 Not Found (entity silently dropped via EVM address)
```

### Citations

**File:** rest/service/entityService.js (L17-20)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L42-53)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);

    if (isEmpty(rows)) {
      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching alias ${accountAlias}`);
      throw new Error(EntityService.multipleAliasMatch);
    }

    return new Entity(rows[0]);
  }
```

**File:** rest/service/entityService.js (L90-103)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }

      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching evm address ${entityId}`);
      throw new Error(EntityService.multipleEvmAddressMatch);
    }

    return rows[0].id;
```

**File:** rest/service/entityService.js (L118-127)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
```

**File:** importer/src/main/resources/db/migration/v1/V1.39.1__upsert_support.sql (L1-8)
```sql
-------------------
-- Support upsert (insert and update from temp table) capabilities for updatable domains
-------------------

-- allow nullable on entity deleted as transaction cannot make this assumption on updates
alter table entity
    alter column deleted drop default,
    alter column deleted drop not null;
```

**File:** importer/src/test/java/org/hiero/mirror/importer/repository/upsert/GenericUpsertQueryGeneratorTest.java (L566-566)
```java
                          coalesce(deleted, e_deleted, null),
```
