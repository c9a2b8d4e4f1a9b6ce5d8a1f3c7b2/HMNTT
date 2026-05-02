### Title
Missing `deleted` Filter in `entityExistenceQuery` Causes `isValidAccount()` to Return `true` for Deleted Accounts

### Summary
`EntityService.isValidAccount()` uses `entityExistenceQuery`, which queries the `entity` table by ID alone with no filter on the `deleted` column. Because deleted entities remain in the table with `deleted = true`, any caller supplying a deleted account's numeric ID receives `true`, bypassing the `NotFoundError` guard in downstream API handlers. This allows any unauthenticated user to retrieve staking rewards and token relationship data for accounts that have been deleted on the Hedera network.

### Finding Description
**Exact code path:**

`rest/service/entityService.js` lines 28–30 define:
```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1`;
```
No `deleted` predicate is present.

`isValidAccount()` at lines 60–63 executes this query and returns `!isNil(entity)` — `true` whenever any row exists for the given ID, deleted or not.

**Root cause / failed assumption:** The developer assumed that a row existing in the `entity` table implies a live account. In reality, Hedera soft-deletes entities: the row is retained with `deleted = true`. The two other queries in the same file explicitly guard against this:
- `entityFromAliasQuery` (lines 17–20): `where coalesce(deleted, false) <> true`
- `entityFromEvmAddressQuery` (lines 22–25): `where deleted <> true`

`entityExistenceQuery` is the only query that omits this guard.

**Exploit flow:**
1. Attacker identifies a deleted account's numeric ID (Hedera account IDs are sequential and publicly observable on-chain).
2. Attacker sends `GET /api/v1/accounts/{deletedId}/rewards` or `GET /api/v1/accounts/{deletedId}/tokens`.
3. `accountController.js` line 172 / `tokenController.js` line 68 call `EntityService.isValidAccount(accountId)`.
4. `isValidAccount()` executes `entityExistenceQuery` with no `deleted` filter → finds the soft-deleted row → returns `true`.
5. The `if (!isValidAccount) throw new NotFoundError()` guard is bypassed.
6. The handler proceeds to query and return staking rewards or token relationships for the deleted account, responding `200 OK` with data.

**Why existing checks are insufficient:** The `NotFoundError` guard at `accountController.js:173` and `tokenController.js:69` is the only protection, and it is entirely dependent on `isValidAccount()` returning `false` for deleted accounts — which it never does.

### Impact Explanation
Any unauthenticated external user can enumerate deleted Hedera accounts and retrieve their historical staking reward records and token relationship data via the REST API. The mirror node incorrectly presents deleted entities as valid, violating the Hedera protocol invariant that deleted accounts must not be treated as active. This constitutes unauthorized information disclosure of post-deletion account state and incorrect protocol semantics exposed through the public API.

### Likelihood Explanation
Exploitation requires zero privileges — only knowledge of a deleted account's numeric ID, which is trivially obtainable from any Hedera block explorer or by sequential enumeration. The attack is fully repeatable, requires no special tooling, and can be performed with a single HTTP GET request. The affected endpoints (`/accounts/{id}/rewards`, `/accounts/{id}/tokens`) are standard public REST endpoints.

### Recommendation
Add the `deleted` filter to `entityExistenceQuery` to match the pattern used by the other two queries in the same file:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1
                                 and coalesce(${Entity.DELETED}, false) <> true`;
```

This aligns `isValidAccount()` with the behavior of `entityFromAliasQuery` and `entityFromEvmAddressQuery`, ensuring deleted accounts are correctly rejected at the guard check.

### Proof of Concept
**Precondition:** Account with numeric ID `12345` exists in the mirror node database with `deleted = true`.

**Steps:**
```
# 1. Query staking rewards for the deleted account
GET /api/v1/accounts/0.0.12345/rewards

# Expected: 404 Not Found
# Actual:   200 OK  { "rewards": [...], "links": { "next": null } }

# 2. Query token relationships for the deleted account
GET /api/v1/accounts/0.0.12345/tokens

# Expected: 404 Not Found
# Actual:   200 OK  { "tokens": [...], "links": { "next": null } }
```

**Root trigger (SQL executed by `isValidAccount()`):**
```sql
SELECT type FROM entity WHERE id = 12345;
-- Returns 1 row (deleted=true row still present) → isValidAccount returns true
```

**Contrast with correct behavior (alias path):**
```sql
SELECT id FROM entity WHERE coalesce(deleted, false) <> true AND alias = $1;
-- Returns 0 rows for deleted entity → correctly returns null
```