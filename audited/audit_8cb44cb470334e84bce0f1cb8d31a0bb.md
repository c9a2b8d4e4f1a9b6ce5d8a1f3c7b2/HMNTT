### Title
Missing `permanent_removal` Filter in `entityFromAliasQuery` Allows Permanently Removed Entities to Be Returned as Valid

### Summary
The `entityFromAliasQuery` in `rest/service/entityService.js` filters entities only by `coalesce(deleted, false) <> true`, but does not check the `permanent_removal` column. An entity that was system-deleted (permanent removal) with `deleted = NULL/false` and `permanent_removal = true` will pass the filter and be returned as a live, valid entity to any unprivileged caller who submits its alias.

### Finding Description

**Exact code location:** `rest/service/entityService.js`, lines 17–20 and function `getAccountFromAlias()` at lines 42–53.

```js
// rest/service/entityService.js lines 17-20
static entityFromAliasQuery = `select ${Entity.ID}
                               from ${Entity.tableName}
                               where coalesce(${Entity.DELETED}, false) <> true
                                 and ${Entity.ALIAS} = $1`;
``` [1](#0-0) 

The `Entity` model explicitly defines `PERMANENT_REMOVAL = 'permanent_removal'` as a known column: [2](#0-1) 

`permanent_removal` is a distinct lifecycle flag from `deleted`. `deleted` is set by a user-initiated `CryptoDelete` transaction. `permanent_removal` is set by a system-level operation (e.g., entity expiry/system delete) and can be `true` while `deleted` remains `NULL` or `false`. The query at lines 17–20 only guards against `deleted`, so any entity with `permanent_removal = true` and `deleted IS NULL` (or `false`) passes the filter.

**Exploit flow:**
1. An entity exists in the `entity` table with `alias = <X>`, `deleted = NULL`, `permanent_removal = true`.
2. An unprivileged external user calls any REST endpoint that resolves an alias (e.g., `GET /api/v1/accounts/<alias>`), which internally calls `getAccountFromAlias()`.
3. `getAccountFromAlias()` executes `entityFromAliasQuery` with `$1 = alias`.
4. The query returns the permanently removed entity because `coalesce(NULL, false) <> true` evaluates to `true`.
5. `getAccountFromAlias()` returns a fully constructed `Entity` object for the permanently removed record.
6. Callers such as `getAccountIdFromAlias()` and `getEncodedId()` propagate this entity ID downstream as a valid, live account. [3](#0-2) [4](#0-3) 

### Impact Explanation
The mirror node REST API serves as the authoritative read layer for Hedera network state. Returning a permanently removed entity as valid causes:
- Incorrect account/entity data exported to mirror node consumers (wallets, explorers, dApps).
- Downstream services treating a non-existent entity as live, potentially allowing operations (e.g., token transfers, contract calls routed via alias resolution) to reference an invalid entity ID.
- Data integrity violation: the mirror node's stated contract is to reflect true network state; permanently removed entities must not appear as active records.

Severity: **Medium** — no direct fund loss from the mirror node itself (read-only), but incorrect state propagation to consumers is a real protocol-level data integrity issue.

### Likelihood Explanation
- **No privileges required.** Any external user can submit an alias string to any alias-resolving REST endpoint.
- **Precondition is realistic.** System deletes (entity expiry) set `permanent_removal = true` without necessarily setting `deleted = true`; this is a normal network lifecycle event.
- **Fully repeatable.** The bug is deterministic: every alias lookup for a permanently-removed-but-not-user-deleted entity will return the wrong result.

### Recommendation
Add `coalesce(permanent_removal, false) <> true` to `entityFromAliasQuery`:

```sql
select id
from entity
where coalesce(deleted, false) <> true
  and coalesce(permanent_removal, false) <> true
  and alias = $1
```

Apply the same fix to `entityFromEvmAddressQuery` (lines 22–25), which has the same omission. Also add a test case in `rest/__tests__/service/entityService.test.js` covering an entity with `permanent_removal = true` to assert it is not returned. [5](#0-4) 

### Proof of Concept
1. Insert a row into the `entity` table:
   ```sql
   INSERT INTO entity (id, alias, deleted, permanent_removal, ...)
   VALUES (99999, decode('<base32_alias_bytes>', 'base64'), NULL, true, ...);
   ```
2. Call the mirror node REST API:
   ```
   GET /api/v1/accounts/<base32_alias>
   ```
3. Observe that the response returns account `0.0.99999` with full entity data instead of a 404.
4. Confirm that `getAccountFromAlias()` returned the entity by checking logs — no error is thrown, and the entity is treated as valid throughout the call chain.

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

**File:** rest/service/entityService.js (L71-81)
```javascript
  async getAccountIdFromAlias(accountAlias, requireResult = true) {
    const entity = await this.getAccountFromAlias(accountAlias);
    if (isNil(entity)) {
      if (requireResult) {
        throw new NotFoundError(EntityService.missingAccountAlias);
      }
      return null;
    }

    return entity.id;
  }
```

**File:** rest/model/entity.js (L25-25)
```javascript
  static PERMANENT_REMOVAL = 'permanent_removal';
```
