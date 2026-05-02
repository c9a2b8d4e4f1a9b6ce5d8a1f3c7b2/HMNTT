### Title
`isValidAccount()` Fails to Enforce Entity Type, Exposing Contract Staking Reward Data via Accounts API

### Summary
`EntityService.isValidAccount()` in `rest/service/entityService.js` uses `entityExistenceQuery` which selects the `type` column from the `entity` table but never inspects its value — it only checks whether any row was returned. As a result, the `/api/v1/accounts/{id}/rewards` endpoint accepts CONTRACT entity IDs as valid "accounts," allowing any unauthenticated caller to retrieve staking reward transfer history for contract entities through the accounts API surface.

### Finding Description
**Code path:**

`rest/routes/accountRoute.js` line 16 routes `GET /:id/rewards` to `AccountController.listStakingRewardsByAccountId`.

In `rest/controllers/accountController.js` lines 170–175:
```js
listStakingRewardsByAccountId = async (req, res) => {
  const accountId = await EntityService.getEncodedId(req.params[...]);
  const isValidAccount = await EntityService.isValidAccount(accountId);
  if (!isValidAccount) {
    throw new NotFoundError();
  }
```

`EntityService.isValidAccount()` in `rest/service/entityService.js` lines 60–63:
```js
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity);
}
```

The query used (`entityExistenceQuery`, lines 28–30):
```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1`;
```

**Root cause:** The query intentionally selects `entity.type` (the comment even says "use a small column in existence check"), but `isValidAccount()` discards the returned row entirely — it only checks `!isNil(entity)`. The type value is never read. Any entity — ACCOUNT, CONTRACT, TOPIC, FILE — passes the check as long as it exists.

**Why the check fails:** The function is named `isValidAccount` and is called as a gate for the `/accounts/{id}/rewards` endpoint, implying it should confirm the entity is of type `ACCOUNT`. It does not. A CONTRACT entity with numeric ID `X` will cause `isValidAccount(X)` to return `true`, and the controller proceeds to query `staking_reward_transfer` for that ID.

**Data availability confirmed:** The `staking_reward_transfer` table does store entries for CONTRACT-type entities. This is confirmed by `SqlEntityListenerTest.java` line 2423 which explicitly creates a CONTRACT entity with staking rewards and verifies they are persisted.

### Impact Explanation
An unauthenticated external caller can enumerate staking reward transfer history for any CONTRACT entity by supplying its numeric ID to `GET /api/v1/accounts/{contractId}/rewards`. The endpoint returns HTTP 200 with reward records instead of 404. This constitutes unauthorized cross-resource data access: contract staking reward data is exposed through the accounts API, bypassing the intended resource boundary. While staking reward amounts are on-chain data, the mirror node API is expected to enforce resource-type boundaries (the endpoint is `/accounts/`, not `/contracts/`). The `staking_reward_transfer` table may contain reward history for contracts that have not yet claimed rewards, revealing pending reward accumulation patterns.

### Likelihood Explanation
No authentication or privilege is required. The only precondition is knowing (or guessing) a numeric entity ID that belongs to a CONTRACT — trivially achievable by iterating small integers or querying the `/api/v1/contracts` endpoint. The exploit is fully repeatable and requires a single HTTP GET request. Any external user can perform it.

### Recommendation
Fix `isValidAccount()` to check the returned `type` value against the expected `ACCOUNT` type:

```js
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity) && entity.type === 'ACCOUNT';
}
```

Alternatively, add a `WHERE type = 'ACCOUNT'` clause to `entityExistenceQuery` so the query itself enforces the constraint. The `Entity.TYPE` constant is already defined in `rest/model/entity.js` line 33 and the value is already being fetched — it just needs to be checked.

### Proof of Concept
**Preconditions:** A CONTRACT entity exists in the mirror node database with numeric ID `N` (e.g., `0.0.1234`) and has at least one entry in `staking_reward_transfer`.

**Steps:**
1. Send: `GET /api/v1/accounts/1234/rewards`
2. `getEncodedId("1234")` resolves to the numeric encoded ID for entity `0.0.1234`.
3. `isValidAccount(encodedId)` queries `entity` table, finds the CONTRACT row, returns `true`.
4. `StakingRewardTransferService.getRewards(...)` queries `staking_reward_transfer WHERE account_id = $1` and returns the contract's reward records.
5. **Result:** HTTP 200 response with the contract's staking reward history, instead of the expected HTTP 404. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rest/controllers/accountController.js (L170-175)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```
