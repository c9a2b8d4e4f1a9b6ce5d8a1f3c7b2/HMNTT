### Title
Inconsistent NULL Handling in `entityFromEvmAddressQuery` Causes Valid Entities to Be Silently Excluded in `getTokenRelationships()`

### Summary
In `rest/service/entityService.js`, `entityFromAliasQuery` uses `coalesce(deleted, false) <> true` to correctly treat a NULL `deleted` field as "not deleted," while `entityFromEvmAddressQuery` uses the bare `deleted <> true`, which in SQL evaluates `NULL <> true` to `NULL` (not `TRUE`), silently excluding any entity whose `deleted` column is NULL. Any unprivileged caller querying `/accounts/{evmAddress}/tokens` for such an entity receives a false 404, while the identical account is fully accessible via its alias, producing split-brain account resolution that breaks EVM-address-based smart contract integrations.

### Finding Description
**Exact code path:**

`rest/controllers/tokenController.js` → `getTokenRelationships()` (line 67) calls `EntityService.getEncodedId(req.params[ID_OR_ALIAS_OR_EVM_ADDRESS])`.

Inside `getEncodedId()` (`rest/service/entityService.js`, line 118–137):
- EVM-address input → `getEntityIdFromEvmAddress()` (line 90–104) → executes `entityFromEvmAddressQuery` (lines 22–25).
- Alias input → `getAccountIdFromAlias()` (line 71–81) → executes `entityFromAliasQuery` (lines 17–20).

The two queries:
```sql
-- entityFromAliasQuery (line 17-20) — correct
WHERE coalesce(deleted, false) <> true   -- NULL → false → false <> true → TRUE (row included)

-- entityFromEvmAddressQuery (line 22-25) — buggy
WHERE deleted <> true                    -- NULL <> true → NULL → row EXCLUDED
```

When `deleted IS NULL` (the normal state for entities that have never been explicitly deleted or confirmed), `entityFromEvmAddressQuery` returns zero rows. `getEntityIdFromEvmAddress()` then throws `NotFoundError` (line 93–95), and the `isValidAccount()` guard at tokenController.js line 68–71 is never reached. The identical entity is found without error when addressed by alias.

**Root cause:** The developer applied `coalesce` defensively only to the alias path, leaving the EVM-address path with a bare `<> true` comparison that is broken by SQL three-valued logic.

### Impact Explanation
Any valid, active account whose `deleted` column is NULL — a common state for accounts that were created but never had an explicit delete/undelete transaction recorded — is invisible to the EVM-address resolution path of the REST API. Smart contract integrations, wallets, and dApps that canonically identify accounts by their EVM address (the standard in EVM ecosystems) will receive spurious 404 responses for these accounts. This causes token-relationship queries to fail silently, breaking token-gating logic, balance checks, and any workflow that chains EVM-address lookups. No funds are directly at risk, but the inconsistency can cause integrations to treat live accounts as non-existent, leading to incorrect smart contract state or failed transactions.

### Likelihood Explanation
No privilege is required. Any external user or automated system can trigger this by supplying a valid EVM address for an account with `deleted = NULL`. Newly imported accounts frequently have `deleted = NULL` until an explicit delete event is processed. The trigger is a standard, unauthenticated GET request to `/accounts/{evmAddress}/tokens`. The condition is persistent (it does not self-heal) and is repeatable on every request for the affected account.

### Recommendation
Apply `coalesce` consistently in `entityFromEvmAddressQuery`, mirroring the alias query:

```js
// rest/service/entityService.js, line 22-25
static entityFromEvmAddressQuery = `select ${Entity.ID}
                                    from ${Entity.tableName}
                                    where coalesce(${Entity.DELETED}, false) <> true
                                      and ${Entity.EVM_ADDRESS} = $1`;
```

Audit all other queries in the REST layer for the same pattern (`deleted <> true` without `coalesce`) and apply the same fix uniformly.

### Proof of Concept
1. Insert an entity row into the mirror-node database with `evm_address = '\xdeadbeef...'`, `alias = 'SOMEALIASVALUE'`, and `deleted = NULL` (do not set `deleted = false`).
2. Send `GET /api/v1/accounts/0xdeadbeef.../tokens` → observe HTTP 404 ("Not Found").
3. Send `GET /api/v1/accounts/SOMEALIASVALUE/tokens` for the same entity → observe HTTP 200 with token relationships returned.
4. Update the row to set `deleted = false` (explicit false, not NULL).
5. Repeat step 2 → now observe HTTP 200, confirming the bug is solely due to the missing `coalesce` on the EVM-address path.