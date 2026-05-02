### Title
`isValidAccount()` Accepts Deleted Entities — Staking Rewards Exposed for Deleted Accounts

### Summary
`EntityService.isValidAccount()` uses `entityExistenceQuery`, which queries the `entity` table **without filtering on `deleted`**. As a result, any unprivileged caller who supplies a numeric account ID belonging to a deleted entity will pass the existence check in `listStakingRewardsByAccountId`, and the full staking reward transfer history for that deleted account is returned instead of a 404.

### Finding Description

**Root cause — missing `deleted` filter in `entityExistenceQuery`:**

`rest/service/entityService.js` defines three queries. Two of them correctly exclude deleted entities:

```js
// alias lookup — filters deleted
where coalesce(${Entity.DELETED}, false) <> true and ${Entity.ALIAS} = $1

// evm-address lookup — filters deleted
where ${Entity.DELETED} <> true and ${Entity.EVM_ADDRESS} = $1
```

But the existence-check query used by `isValidAccount()` does **not**:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1`;   // ← no deleted filter
``` [1](#0-0) 

`isValidAccount()` simply checks whether any row was returned:

```js
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity);   // true even when deleted=true
}
``` [2](#0-1) 

**Exploit path in `listStakingRewardsByAccountId`:**

```js
listStakingRewardsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[...]);
  const isValidAccount = await EntityService.isValidAccount(accountId);
  if (!isValidAccount) {
    throw new NotFoundError();   // ← never reached for deleted accounts
  }
  // proceeds to query staking_reward_transfer for the deleted account
  const stakingRewardsTransfers = await StakingRewardTransferService.getRewards(...);
``` [3](#0-2) 

Because `entityExistenceQuery` returns a row for a deleted entity (the row still exists in the `entity` table with `deleted = true`), `isValidAccount()` returns `true`, the `NotFoundError` is never thrown, and the full staking reward transfer history is served.

Note: the alias and EVM-address resolution paths (`entityFromAliasQuery`, `entityFromEvmAddressQuery`) both carry explicit `deleted <> true` guards, confirming the design intent is to hide deleted entities — the numeric-ID path is simply missing the same guard. [4](#0-3) 

### Impact Explanation
Any external, unauthenticated caller can enumerate staking reward transfer records for accounts that have been deleted from the network. The REST API is supposed to return HTTP 404 for deleted accounts (consistent with alias/EVM-address lookups), but instead returns HTTP 200 with the full reward history. This is an unauthorized information-disclosure of financial history that the protocol explicitly marks as inaccessible post-deletion.

### Likelihood Explanation
No privileges are required. The attacker only needs to know (or brute-force) a numeric account ID (`0.0.<num>`) of a deleted account. Account IDs are sequential integers, making enumeration trivial. The endpoint is publicly reachable at `/api/v1/accounts/<id>/rewards`. The attack is fully repeatable and requires no special tooling beyond a standard HTTP client.

### Recommendation
Add a `deleted` filter to `entityExistenceQuery`, matching the pattern already used by the other two queries:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where coalesce(${Entity.DELETED}, false) <> true
                                 and ${Entity.ID} = $1`;
```

This makes `isValidAccount()` return `false` for deleted entities, causing `listStakingRewardsByAccountId` to throw `NotFoundError` (HTTP 404) as intended.

### Proof of Concept

**Preconditions:**
1. Account `0.0.1234` exists in the `entity` table with `deleted = true` (it was deleted on-chain).
2. One or more rows exist in `staking_reward_transfer` for `account_id = <encoded id of 0.0.1234>`.

**Steps:**
```
GET /api/v1/accounts/1234/rewards
```

**Expected result (correct behaviour):** HTTP 404 — account is deleted.

**Actual result (vulnerable behaviour):** HTTP 200 with the full staking reward transfer history for the deleted account, e.g.:
```json
{
  "rewards": [
    {"account_id": "0.0.1234", "amount": 5000000, "timestamp": "1700000000.000000000"}
  ],
  "links": {"next": null}
}
```

The same request using an alias or EVM address for the same deleted account correctly returns 404, confirming the inconsistency is isolated to the numeric-ID code path.

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

**File:** rest/controllers/accountController.js (L170-185)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
    const filters = utils.buildAndValidateFilters(req.query, acceptedRewardsParameters);
    const query = this.extractStakingRewardsQuery(filters);
    // insert account id at $1, and limit (at $2)
    query.params.unshift(accountId, query.limit);
    const stakingRewardsTransfers = await StakingRewardTransferService.getRewards(
      query.order,
      query.limit,
      query.conditions,
      query.params
    );
```
