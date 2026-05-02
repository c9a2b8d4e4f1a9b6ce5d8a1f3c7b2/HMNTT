### Title
Missing `coalesce()` on Nullable `deleted` Column in `entityFromEvmAddressQuery` Causes Silent Entity Omission

### Summary
In `rest/service/entityService.js`, the `entityFromEvmAddressQuery` uses `deleted <> true` without a `coalesce()` guard. Because the `entity.deleted` column is explicitly nullable (per migration `V1.39.1__upsert_support.sql`), any entity with `deleted IS NULL` evaluates `NULL <> true` as SQL NULL (falsy), causing the WHERE clause to silently exclude that row. The sibling query `entityFromAliasQuery` correctly uses `coalesce(deleted, false) <> true`, making this an inconsistency with a concrete, exploitable impact.

### Finding Description

**Exact code location:** `rest/service/entityService.js`, lines 22–25, static field `entityFromEvmAddressQuery`, consumed by `getEntityIdFromEvmAddress()` at line 91.

```js
// VULNERABLE — missing coalesce
static entityFromEvmAddressQuery = `select ${Entity.ID}
                                    from ${Entity.tableName}
                                    where ${Entity.DELETED} <> true
                                      and ${Entity.EVM_ADDRESS} = $1`;
```

**Correct sibling query** (`entityFromAliasQuery`, lines 17–20):
```js
// CORRECT — coalesce handles NULL
static entityFromAliasQuery = `select ${Entity.ID}
                               from ${Entity.tableName}
                               where coalesce(${Entity.DELETED}, false) <> true
                                 and ${Entity.ALIAS} = $1`;
```

**Root cause:** SQL three-valued logic. When `deleted IS NULL`:
- `NULL <> true` → evaluates to `NULL`, not `TRUE`
- A `NULL` predicate in a `WHERE` clause is treated as falsy → row excluded

**`deleted` is explicitly nullable:** Migration `V1.39.1__upsert_support.sql` drops both the `NOT NULL` constraint and the `DEFAULT false` from the `entity.deleted` column, with the comment *"allow nullable on entity deleted as transaction cannot make this assumption on updates"*. This is a documented, intentional schema state, not a data anomaly.

**Exploit flow:**
1. An entity exists in the `entity` table with `evm_address` set and `deleted IS NULL` (valid per schema).
2. An unprivileged external user sends any REST request that resolves an EVM address, e.g. `GET /api/v1/contracts/0x<evmAddress>` or `GET /api/v1/accounts/0x<evmAddress>`.
3. The request reaches `getEntityIdFromEvmAddress()` → executes `entityFromEvmAddressQuery`.
4. The SQL `WHERE deleted <> true AND evm_address = $1` returns zero rows because `NULL <> true` is NULL.
5. `rows.length === 0` → `requireResult=true` path throws `NotFoundError` (line 94), or returns `null` (line 97).
6. The caller propagates a 404 / missing-record response to the user.

**Existing checks are insufficient:** The only guard is the `rows.length === 0` check at line 92, which is the symptom of the bug, not a mitigation. There is no application-layer fallback that re-queries without the `deleted` filter.

### Impact Explanation

Any entity whose `deleted` column is NULL — a valid, schema-permitted state — is permanently invisible to all EVM-address-based lookups through the mirror node REST API. This produces incorrect "Not Found" (404) responses for accounts and contracts that genuinely exist and are not deleted. Downstream consumers (wallets, explorers, dApps) relying on EVM address resolution will receive false negatives, leading to incorrect balance displays, failed contract interactions, and broken address-to-entity mappings. Severity: **Medium** (data integrity / availability; no fund loss, but persistent incorrect state visible to all users).

### Likelihood Explanation

No privileges are required. Any user who knows or discovers an EVM address of an affected entity can trigger the bug deterministically and repeatedly by issuing a standard REST GET request. The condition (`deleted IS NULL`) is an explicitly supported schema state, so affected entities can exist in any production deployment. The bug is stable — it does not require a race condition or timing window.

### Recommendation

Apply the same `coalesce()` pattern already used in `entityFromAliasQuery`:

```js
// rest/service/entityService.js, lines 22-25
static entityFromEvmAddressQuery = `select ${Entity.ID}
                                    from ${Entity.tableName}
                                    where coalesce(${Entity.DELETED}, false) <> true
                                      and ${Entity.EVM_ADDRESS} = $1`;
```

This makes `NULL` treated as `false` (not deleted), consistent with the alias query and with the semantic intent of the `deleted` column.

### Proof of Concept

**Precondition:** Insert an entity with `deleted = NULL` and a known EVM address directly into the database (this is a valid state per `V1.39.1__upsert_support.sql`):

```sql
INSERT INTO entity (id, num, realm, shard, type, evm_address, deleted)
VALUES (1001, 1001, 0, 0, 'CONTRACT',
        decode('abcdef1234567890abcdef1234567890abcdef12', 'hex'),
        NULL);  -- deleted IS NULL, not deleted = false
```

**Trigger:** Query the mirror node REST API as an unprivileged user:

```
GET /api/v1/contracts/0xabcdef1234567890abcdef1234567890abcdef12
```

**Expected result (correct behavior):** HTTP 200 with contract details.

**Actual result (buggy behavior):** HTTP 404 `{"_status":{"messages":[{"message":"Not found"}]}}` — because `entityFromEvmAddressQuery` evaluates `NULL <> true` as NULL, returns zero rows, and `getEntityIdFromEvmAddress()` throws `NotFoundError` at line 94.

**Contrast:** Querying the same entity by alias (if it has one) succeeds, because `entityFromAliasQuery` uses `coalesce(deleted, false) <> true`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/service/entityService.js (L90-104)
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
