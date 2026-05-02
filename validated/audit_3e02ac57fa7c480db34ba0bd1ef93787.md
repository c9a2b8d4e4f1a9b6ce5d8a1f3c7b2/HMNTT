The code confirms the claim. Both queries are present exactly as described:

- `entityFromAliasQuery` (lines 17–20): uses `coalesce(${Entity.DELETED}, false) <> true` [1](#0-0) 
- `entityFromEvmAddressQuery` (lines 22–25): uses bare `${Entity.DELETED} <> true` without `coalesce` [2](#0-1) 
- `getEntityIdFromEvmAddress()` throws `NotFoundError` when zero rows are returned [3](#0-2) 
- `getTokenRelationships` calls `EntityService.getEncodedId()` and the `NotFoundError` propagates before `isValidAccount` is ever reached [4](#0-3) 

---

## Audit Report

## Title
Inconsistent NULL Handling in `entityFromEvmAddressQuery` Causes Valid Entities to Be Silently Excluded in `getTokenRelationships()`

## Summary
`entityFromAliasQuery` uses `coalesce(deleted, false) <> true` to correctly treat a NULL `deleted` field as "not deleted," while `entityFromEvmAddressQuery` uses the bare `deleted <> true`. In SQL three-valued logic, `NULL <> true` evaluates to `NULL` (not `TRUE`), so any entity with `deleted IS NULL` is silently excluded from the EVM-address lookup path but correctly returned by the alias lookup path.

## Finding Description
In `rest/service/entityService.js`:

```sql
-- entityFromAliasQuery (lines 17–20) — correct
WHERE coalesce(deleted, false) <> true   -- NULL → false → false <> true → TRUE (row included)

-- entityFromEvmAddressQuery (lines 22–25) — inconsistent
WHERE deleted <> true                    -- NULL <> true → NULL → row EXCLUDED
```

The call chain for `/accounts/{evmAddress}/tokens`:

1. `tokenController.js` line 67: `EntityService.getEncodedId(req.params[ID_OR_ALIAS_OR_EVM_ADDRESS])`
2. `entityService.js` line 124: routes EVM-address input to `getEntityIdFromEvmAddress()`
3. `entityService.js` lines 91–94: executes `entityFromEvmAddressQuery`; if zero rows returned (because `deleted IS NULL` causes the WHERE clause to evaluate to `NULL`), throws `NotFoundError` immediately
4. Control never reaches the `isValidAccount()` guard at `tokenController.js` lines 68–71

The identical entity is found without error when addressed by alias, because `entityFromAliasQuery` wraps the column in `coalesce`.

## Impact Explanation
Any valid, active account whose `deleted` column is `NULL` — a normal state for accounts that have never had an explicit delete/undelete transaction recorded — is invisible to the EVM-address resolution path of the REST API. Callers querying `/accounts/{evmAddress}/tokens` for such an account receive a false 404. Smart contract integrations, wallets, and dApps that canonically identify accounts by EVM address will treat live accounts as non-existent, breaking token-relationship queries, token-gating logic, and balance checks. The same account is fully accessible via its alias, producing split-brain account resolution.

## Likelihood Explanation
No privilege is required. Any external user or automated system can trigger this by supplying a valid EVM address for an account with `deleted = NULL`. Newly created or imported accounts frequently have `deleted = NULL` until an explicit delete event is processed. The trigger is a standard, unauthenticated GET request to `/accounts/{evmAddress}/tokens`. The condition is persistent and repeatable on every request for the affected account.

## Recommendation
Apply the same `coalesce` guard to `entityFromEvmAddressQuery` as is already used in `entityFromAliasQuery`:

```js
// rest/service/entityService.js, lines 22–25
static entityFromEvmAddressQuery = `select ${Entity.ID}
                                    from ${Entity.tableName}
                                    where coalesce(${Entity.DELETED}, false) <> true
                                      and ${Entity.EVM_ADDRESS} = $1`;
```

This makes the NULL-handling semantics consistent across both resolution paths.

## Proof of Concept
1. Insert an entity row with `evm_address = <addr>`, `alias = <alias>`, `deleted = NULL`.
2. `GET /accounts/<alias>/tokens` → 200 OK (alias path uses `coalesce`, row is found).
3. `GET /accounts/<evmAddress>/tokens` → 404 Not Found (EVM-address path omits `coalesce`, `NULL <> true` → `NULL`, row excluded, `NotFoundError` thrown at `entityService.js` line 94).

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

**File:** rest/service/entityService.js (L92-95)
```javascript
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }
```

**File:** rest/controllers/tokenController.js (L67-71)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```
