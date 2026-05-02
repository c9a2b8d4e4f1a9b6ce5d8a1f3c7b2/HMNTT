### Title
`isValidAccount()` Returns `true` for Soft-Deleted Entities Due to Missing `deleted` Filter in `entityExistenceQuery`

### Summary
The `entityExistenceQuery` SQL statement used by `isValidAccount()` in `rest/service/entityService.js` omits a filter on the `deleted` column, causing it to match entities regardless of their deletion status. Any unprivileged external user who supplies the numeric ID of a soft-deleted account will receive a `true` validity result, bypassing the intended `NotFoundError` guard and causing the mirror node to serve data for deleted accounts as if they were active.

### Finding Description
**Exact code path:**

In `rest/service/entityService.js` lines 28–30, `entityExistenceQuery` is defined as:
```sql
select ${Entity.TYPE}
from ${Entity.tableName}
where ${Entity.ID} = $1
```
No `deleted` predicate is present.

`isValidAccount()` (lines 60–63) executes this query and returns `true` whenever any row is found:
```js
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity);
}
```

**Contrast with sibling queries in the same file:**
- `entityFromAliasQuery` (lines 17–20): `where coalesce(${Entity.DELETED}, false) <> true`
- `entityFromEvmAddressQuery` (lines 22–25): `where ${Entity.DELETED} <> true`

Both correctly exclude soft-deleted rows; `entityExistenceQuery` does not.

**Exploit flow:**
1. A previously-deleted account exists in the `entity` table with `deleted = true` and a known numeric ID (e.g., `0.0.12345`).
2. An attacker sends `GET /api/v1/accounts/0.0.12345/rewards`.
3. `accountController.js` line 172 calls `EntityService.isValidAccount(accountId)`.
4. `entityExistenceQuery` matches the row (no deleted filter) and returns it.
5. `isNil(entity)` is `false`, so `isValidAccount` returns `true`.
6. The `NotFoundError` guard at line 173–175 is bypassed.
7. The endpoint proceeds to query and return staking reward data for the deleted account.

The same guard pattern is used in `tokenController.js` (2 call sites), broadening the affected surface.

**Test gap confirmed:** The test suite at `rest/__tests__/service/entityService.test.js` lines 148–158 only covers "no entity exists" and "entity exists (not deleted)" — there is no test for a deleted entity, so this path has never been exercised.

### Impact Explanation
Mirror node REST API endpoints that are supposed to return `404 Not Found` for deleted accounts instead return valid responses. This violates the protocol invariant that deleted accounts are no longer active participants. Downstream consumers (wallets, explorers, indexers) that rely on the mirror node to distinguish active from deleted accounts will receive incorrect state, potentially leading to erroneous balance/reward displays or incorrect business logic decisions. Severity is **Medium**: data integrity is compromised but no funds are directly at risk.

### Likelihood Explanation
Exploitation requires zero privileges — only a valid numeric account ID of a previously-deleted entity, which is publicly observable on-chain or via other mirror node queries (e.g., transaction history). The attack is trivially repeatable with a simple HTTP GET request. Any deleted account ID is a valid trigger.

### Recommendation
Add a `deleted` filter to `entityExistenceQuery` consistent with the other queries in the same file:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1
                                 and coalesce(${Entity.DELETED}, false) <> true`;
```

Additionally, add a test case to `entityService.test.js` that loads a deleted entity (`deleted: true`) and asserts `isValidAccount()` returns `false`.

### Proof of Concept
**Precondition:** Entity with `id = X` exists in the `entity` table with `deleted = true`.

**Steps:**
1. Identify a deleted account ID `X` (e.g., from transaction history via `GET /api/v1/transactions`).
2. Send: `GET /api/v1/accounts/{X}/rewards`
3. **Expected:** `404 Not Found`
4. **Actual:** `200 OK` with staking rewards data — `isValidAccount()` returned `true` because `entityExistenceQuery` matched the deleted row.

**Minimal reproduction (pseudo-SQL to confirm):**
```sql
-- Insert a deleted entity
INSERT INTO entity (id, type, deleted) VALUES (99999, 'ACCOUNT', true);

-- entityExistenceQuery will return a row:
SELECT type FROM entity WHERE id = 99999;
-- Returns: 1 row → isValidAccount = true (WRONG)

-- Correct query would return nothing:
SELECT type FROM entity WHERE id = 99999 AND coalesce(deleted, false) <> true;
-- Returns: 0 rows → isValidAccount = false (CORRECT)
```