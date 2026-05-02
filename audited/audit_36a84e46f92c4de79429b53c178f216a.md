### Title
`isValidAccount()` Missing Deleted-Account Filter Causes 200 OK for Deleted Accounts Instead of 404

### Summary
`EntityService.isValidAccount()` uses `entityExistenceQuery`, which queries the `entity` table by ID only, with no filter on the `deleted` column. A deleted account still has a row in the `entity` table with `deleted = true`, so `isValidAccount()` returns `true`. The subsequent `TokenService.getTokenAccounts()` call finds no associated tokens and returns an empty list, causing the API to respond `200 OK {"tokens": [], "links": {"next": null}}` instead of `404 Not Found`. Any unprivileged external user can trigger this deterministically — no network partition is required.

### Finding Description
In `rest/service/entityService.js`, the existence check query is:

```js
// lines 28-30
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1`;
```

There is no `deleted` filter. Compare with `entityFromAliasQuery` (lines 17-20), which correctly excludes deleted entities:

```js
where coalesce(${Entity.DELETED}, false) <> true
  and ${Entity.ALIAS} = $1
```

`isValidAccount()` (lines 60-63) calls `getSingleRow` with `entityExistenceQuery` and returns `!isNil(entity)`. For a deleted account, the row still exists in the `entity` table with `deleted = true`, so `isNil(entity)` is `false` and the method returns `true`.

In `getTokenRelationships()` (lines 66-92 of `rest/controllers/tokenController.js`):
- Line 68: `isValidAccount()` returns `true` for the deleted account → no `NotFoundError` thrown.
- Line 74: `TokenService.getTokenAccounts()` queries `token_account` where `associated = true` — a deleted account has no active associations, so it returns `[]`.
- Lines 86-91: The response is `200 OK` with `{"tokens": [], "links": {"next": null}}`.

### Impact Explanation
Any caller querying `/accounts/{deletedAccountId}/tokens` receives a `200 OK` with an empty token list, which is semantically indistinguishable from a valid account that holds no tokens. Clients and downstream systems cannot distinguish "account does not exist" from "account exists but has no token relationships." This breaks the API contract, can mislead integrators into treating deleted accounts as active, and may cause incorrect business logic in wallets, explorers, or compliance tools that rely on this endpoint.

### Likelihood Explanation
This is trivially exploitable by any unprivileged user with knowledge of a previously-deleted account ID (which is public information on a mirror node). No special timing, network conditions, or elevated access is required. The trigger is a single HTTP GET request. It is 100% reproducible as long as the account row remains in the `entity` table with `deleted = true`.

### Recommendation
Add a `deleted` filter to `entityExistenceQuery` in `rest/service/entityService.js`, consistent with how `entityFromAliasQuery` already handles it:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1
                                 and coalesce(${Entity.DELETED}, false) <> true`;
```

### Proof of Concept
1. Identify or create an account on the network, note its numeric ID (e.g., `0.0.12345`).
2. Delete the account (via a `CryptoDelete` transaction). The `entity` row now has `deleted = true`.
3. Send: `GET /api/v1/accounts/0.0.12345/tokens`
4. **Expected:** `404 Not Found`
5. **Actual:** `200 OK` with body `{"tokens": [], "links": {"next": null}}`

The root cause is confirmed at:
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2)

### Citations

**File:** rest/service/entityService.js (L28-30)
```javascript
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

**File:** rest/controllers/tokenController.js (L66-74)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenParameters);
    const query = this.extractTokensRelationshipQuery(filters, accountId);
    const tokenRelationships = await TokenService.getTokenAccounts(query);
```
