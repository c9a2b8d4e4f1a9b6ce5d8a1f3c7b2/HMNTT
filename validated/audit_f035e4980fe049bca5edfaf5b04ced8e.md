All claims in the report are verified against the actual code. The vulnerability is real and accurately described.

---

Audit Report

## Title
Missing `deleted` Filter in `entityExistenceQuery` Causes `isValidAccount()` to Return `true` for Deleted Accounts

## Summary
`EntityService.isValidAccount()` queries the `entity` table by ID only, with no filter on the `deleted` column. Because Hedera soft-deletes entities (retaining rows with `deleted = true`), the function returns `true` for deleted accounts. The `NotFoundError` guards in `accountController.js` and `tokenController.js` are entirely dependent on this function, so they are bypassed, allowing callers to retrieve staking rewards and token relationships for deleted accounts.

## Finding Description
`entityExistenceQuery` is defined at lines 28–30 of `rest/service/entityService.js` with no `deleted` predicate:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1`;
``` [1](#0-0) 

`isValidAccount()` at lines 60–63 executes this query and returns `!isNil(entity)` — `true` whenever any row exists for the given ID, regardless of deletion status: [2](#0-1) 

The inconsistency is clear when compared to the two other queries in the same file, which both explicitly guard against deleted entities:

- `entityFromAliasQuery` (lines 17–20): `where coalesce(deleted, false) <> true`
- `entityFromEvmAddressQuery` (lines 22–25): `where deleted <> true` [3](#0-2) 

`entityExistenceQuery` is the only query in the file that omits this guard.

The sole protection in both affected controllers is the `isValidAccount()` check:

- `accountController.js` lines 172–174 (`listStakingRewardsByAccountId`): [4](#0-3) 

- `tokenController.js` lines 68–70 (`getTokenRelationships`): [5](#0-4) 

The test suite for `isValidAccount` (lines 148–158) only covers "no row" and "row exists" cases — there is no test for a deleted entity, confirming the gap was never caught: [6](#0-5) 

## Impact Explanation
Any unauthenticated caller can supply a deleted account's numeric ID to `/api/v1/accounts/{id}/rewards` or `/api/v1/accounts/{id}/tokens` and receive a `200 OK` response with staking reward records or token relationship data. This constitutes unauthorized information disclosure of post-deletion account state and violates the Hedera protocol invariant that deleted accounts must not be treated as active.

## Likelihood Explanation
Exploitation requires zero privileges. Hedera account IDs are sequential and publicly observable on any block explorer, making enumeration of deleted accounts trivial. The attack requires only a single HTTP GET request with no special tooling.

## Recommendation
Add a `deleted` filter to `entityExistenceQuery` consistent with the pattern already used by the other two queries in the same file:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where coalesce(${Entity.DELETED}, false) <> true
                                 and ${Entity.ID} = $1`;
```

Using `coalesce(..., false)` (matching `entityFromAliasQuery`) is preferred over a bare `<> true` (matching `entityFromEvmAddressQuery`) because it correctly handles rows where `deleted` is `NULL`.

A test case should also be added to `entityService.test.js` that loads an entity with `deleted = true` and asserts that `isValidAccount()` returns `false`.

## Proof of Concept
1. Identify any deleted account's numeric ID (e.g., from a Hedera block explorer).
2. Send: `GET /api/v1/accounts/{deletedId}/rewards`
3. `accountController.js:172` calls `EntityService.isValidAccount(accountId)`.
4. `isValidAccount()` executes `entityExistenceQuery` — finds the soft-deleted row — returns `true`.
5. The `NotFoundError` guard at line 173 is not triggered.
6. The handler queries and returns staking reward data with `200 OK`.

The same flow applies to `GET /api/v1/accounts/{deletedId}/tokens` via `tokenController.js:68–70`.

### Citations

**File:** rest/service/entityService.js (L17-25)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;

  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L27-30)
```javascript
  // use a small column in existence check to reduce return payload size
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/controllers/accountController.js (L172-175)
```javascript
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/controllers/tokenController.js (L68-71)
```javascript
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/__tests__/service/entityService.test.js (L148-158)
```javascript
describe('EntityService.isValidAccount tests', () => {
  test('EntityService.isValidAccount - No match', async () => {
    await expect(EntityService.isValidAccount(defaultInputEntity[0].id)).resolves.toBe(false);
  });

  test('EntityService.getAccountFromAlias - Matching', async () => {
    await integrationDomainOps.loadEntities(defaultInputEntity);

    await expect(EntityService.isValidAccount(defaultInputEntity[0].id)).resolves.toBe(true);
  });
});
```
