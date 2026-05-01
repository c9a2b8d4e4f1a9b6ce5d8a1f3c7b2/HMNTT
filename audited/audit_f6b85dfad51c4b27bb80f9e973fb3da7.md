### Title
`isValidAccount()` Accepts Deleted Accounts, Exposing Stale Token Relationship Data via `/accounts/:id/tokens`

### Summary
`EntityService.isValidAccount()` uses `entityExistenceQuery`, which queries the `entity` table by ID alone with no filter on the `deleted` column. As a result, `getTokenRelationships()` passes the validity check for deleted accounts and proceeds to return their stale `token_account` records. Any unprivileged caller can retrieve token relationship data (balances, freeze/KYC status) for accounts that no longer exist on-chain.

### Finding Description
**Root cause — `entityExistenceQuery` missing `deleted` filter:**

`rest/service/entityService.js` lines 28–30:
```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1`;
```
No `deleted` predicate. Compare with the two sibling queries in the same file that correctly exclude deleted entities:
- `entityFromAliasQuery` (line 19): `coalesce(${Entity.DELETED}, false) <> true`
- `entityFromEvmAddressQuery` (line 24): `${Entity.DELETED} <> true`

**`isValidAccount()` returns `true` for deleted accounts:**

`rest/service/entityService.js` lines 60–63:
```js
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity);   // true even when entity.deleted = true
}
```

**`getTokenRelationships()` proceeds past the guard:**

`rest/controllers/tokenController.js` lines 66–71:
```js
getTokenRelationships = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[...]);
  const isValidAccount = await EntityService.isValidAccount(accountId);
  if (!isValidAccount) { throw new NotFoundError(); }   // never thrown for deleted accounts
  ...
  const tokenRelationships = await TokenService.getTokenAccounts(query);
```

When the path parameter is a plain `shard.realm.num` entity ID, `getEncodedId()` returns the encoded ID via pure parsing (no DB lookup, no deleted check). `isValidAccount()` then confirms the entity row exists — which it does even after deletion — and the guard is bypassed.

**`tokenRelationshipsQuery` also has no deleted guard:**

`rest/service/tokenService.js` lines 20–29:
```sql
select ... from token_account ta
where ta.account_id = $1 and ta.associated = true
```
No join back to `entity` to verify the account is still alive. All `token_account` rows with `associated = true` are returned regardless of the owning account's deletion state.

**Exploit flow:**
1. Account `0.0.9999` is deleted on-chain; its row in `entity` remains with `deleted = true`.
2. Attacker sends: `GET /api/v1/accounts/0.0.9999/tokens`
3. `getEncodedId("0.0.9999")` → returns encoded ID (no DB check).
4. `isValidAccount(encodedId)` → `entityExistenceQuery` finds the row, returns `true`.
5. `TokenService.getTokenAccounts()` returns all `token_account` rows for that account.
6. API responds HTTP 200 with stale token balances, freeze status, KYC status.

### Impact Explanation
Off-chain systems and smart contract integrations that consult the mirror node REST API to determine whether an account holds or is associated with a token will receive affirmative, stale data for deleted accounts. A smart contract workflow that gates an action on "does account X hold token Y?" (by reading mirror node data) can be tricked into proceeding when the account no longer exists on-chain. While the Hedera consensus node would reject any subsequent on-chain transaction referencing the deleted account, the mirror node response can cause incorrect branching in off-chain logic, incorrect UI state, or incorrect pre-condition checks in contract-calling scripts — matching the stated severity of unintended smart contract behavior with no direct fund loss.

### Likelihood Explanation
No authentication or special privilege is required. The endpoint is public. Any attacker who knows (or can enumerate) a previously-deleted account ID can trigger this at will, repeatedly, with a single HTTP GET request. Deleted account IDs are discoverable from the mirror node's own transaction history endpoints.

### Recommendation
Add a `deleted` filter to `entityExistenceQuery` in `rest/service/entityService.js`, consistent with the other two queries in the same class:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1
                                 and coalesce(${Entity.DELETED}, false) <> true`;
```

This single change makes `isValidAccount()` return `false` for deleted accounts, causing `getTokenRelationships()` to throw `NotFoundError` (HTTP 404) as intended.

### Proof of Concept
```
# 1. Identify a deleted account (e.g., from transaction history)
GET /api/v1/transactions?transactiontype=CRYPTODELETE&limit=1
# Note the deleted account ID, e.g. 0.0.9999

# 2. Confirm it is deleted (accounts endpoint returns deleted:true or 404 depending on impl)
GET /api/v1/accounts/0.0.9999

# 3. Query token relationships — should return 404 but returns 200 with stale data
GET /api/v1/accounts/0.0.9999/tokens

# Expected: HTTP 404 Not Found
# Actual:   HTTP 200 with token relationship records (balance, freeze_status, kyc_status)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rest/service/tokenService.js (L20-29)
```javascript
  static tokenRelationshipsQuery = `
        select ${TokenAccount.getFullName(TokenAccount.AUTOMATIC_ASSOCIATION)},
               ${TokenAccount.getFullName(TokenAccount.BALANCE)},
               ${TokenAccount.getFullName(TokenAccount.CREATED_TIMESTAMP)},
               ${TokenAccount.getFullName(TokenAccount.FREEZE_STATUS)},
               ${TokenAccount.getFullName(TokenAccount.KYC_STATUS)},
               ${TokenAccount.getFullName(TokenAccount.TOKEN_ID)}
        from ${TokenAccount.tableName} ${TokenAccount.tableAlias}
        where ${TokenAccount.tableAlias}.${TokenAccount.ACCOUNT_ID} = $1
        and ${TokenAccount.tableAlias}.${TokenAccount.ASSOCIATED} = true `;
```
