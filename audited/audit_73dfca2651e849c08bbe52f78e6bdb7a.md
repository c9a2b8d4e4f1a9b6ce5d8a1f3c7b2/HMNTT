### Title
Deleted Account Staking Reward History Exposed via Missing `deleted` Filter in `isValidAccount()`

### Summary
`EntityService.isValidAccount()` uses `entityExistenceQuery`, which queries the `entity` table by ID alone with no `deleted` filter. As a result, any account that has been deleted still passes the validity gate in `listStakingRewardsByAccountId`, and the API returns that account's full historical staking reward transfer records instead of a 404. Every other lookup path in the same service explicitly excludes deleted entities, making this an inconsistent and exploitable omission.

### Finding Description

**Code path:**

`rest/routes/accountRoute.js` → `AccountController.listStakingRewardsByAccountId` → `EntityService.isValidAccount()` → `entityExistenceQuery`

**Root cause — `rest/service/entityService.js` lines 28–30:**
```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1`;   // ← no deleted filter
``` [1](#0-0) 

`isValidAccount()` (lines 60–63) calls this query and returns `true` whenever any row is found, regardless of the `deleted` column value:
```js
async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);   // true even when entity.deleted = true
}
``` [2](#0-1) 

**Contrast with every other lookup in the same file**, which correctly excludes deleted entities:
- `entityFromAliasQuery` — `coalesce(deleted, false) <> true` [3](#0-2) 
- `entityFromEvmAddressQuery` — `deleted <> true` [4](#0-3) 

**Controller flow — `rest/controllers/accountController.js` lines 170–185:**

When `isValidAccount` returns `true` for a deleted account, execution continues and `StakingRewardTransferService.getRewards()` is called, which queries `staking_reward_transfer` filtered only by `account_id = $1` — no deletion check there either: [5](#0-4) 

The `staking_reward_transfer` table retains all historical reward records even after an account is deleted. The rewards query:
```sql
select srt.account_id, srt.amount, srt.consensus_timestamp
from staking_reward_transfer srt
where srt.account_id = $1
``` [6](#0-5) 

**Exploit flow:**
1. Attacker identifies a deleted account ID (e.g., `0.0.1234`) — account IDs are sequential and public.
2. Sends `GET /api/v1/accounts/1234/rewards`.
3. `getEncodedId` for a numeric ID performs no DB lookup — it just encodes the integer. [7](#0-6) 
4. `isValidAccount(encodedId)` runs `entityExistenceQuery`; the deleted entity row still exists → returns `true`.
5. Full staking reward transfer history for the deleted account is returned with HTTP 200.

### Impact Explanation

The API is supposed to return 404 for non-existent or deleted accounts (the `isValidAccount` guard exists precisely for this). Instead, deleted accounts' complete staking reward transfer history — amounts and timestamps — is disclosed to any unauthenticated caller. While this endpoint is read-only and cannot redirect funds, it leaks financial history that the account owner deleted and that the protocol should no longer surface. The `entity_state_start` materialized view used for pending-reward calculation correctly applies `deleted is not true`; the REST layer does not, creating an inconsistency between what the protocol considers a live account and what the API exposes. [8](#0-7) 

### Likelihood Explanation

No authentication or special privilege is required. Account IDs are monotonically increasing integers, trivially enumerable. Any external user can iterate IDs and call `/api/v1/accounts/{id}/rewards` to discover which deleted accounts had staking activity and what amounts they received. The exploit is fully repeatable and requires only a standard HTTP client.

### Recommendation

Add a `deleted` filter to `entityExistenceQuery`, consistent with the other two queries in the same class:

```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where coalesce(${Entity.DELETED}, false) <> true
                                 and ${Entity.ID} = $1`;
```

This single change makes `isValidAccount()` return `false` for deleted entities, causing `listStakingRewardsByAccountId` to throw `NotFoundError` (HTTP 404) for deleted accounts, matching the behaviour of alias and EVM-address lookups.

### Proof of Concept

**Preconditions:** Mirror node REST API is running; account `0.0.1234` exists in the `entity` table with `deleted = true` and has rows in `staking_reward_transfer`.

```bash
# Step 1 – confirm account is deleted (direct DB check, attacker infers from prior 404 on /accounts/1234)
# SELECT deleted FROM entity WHERE id = <encoded_1234>;  → true

# Step 2 – call the rewards endpoint as an unprivileged external user
curl -s "http://<mirror-node>/api/v1/accounts/1234/rewards"

# Expected (correct) response: HTTP 404
# Actual (vulnerable) response: HTTP 200 with full reward history, e.g.:
# {
#   "rewards": [
#     {"account_id": "0.0.1234", "amount": 500000, "timestamp": "1680000000.000000000"},
#     ...
#   ],
#   "links": {"next": null}
# }
```

The response leaks the complete staking reward transfer history for a deleted account to an unauthenticated caller.

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

**File:** rest/service/entityService.js (L120-124)
```javascript
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
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

**File:** rest/service/stakingRewardTransferService.js (L11-16)
```javascript
  static listStakingRewardsByAccountIdQuery = `
    select ${StakingRewardTransfer.getFullName(StakingRewardTransfer.ACCOUNT_ID)},
    ${StakingRewardTransfer.getFullName(StakingRewardTransfer.AMOUNT)},
    ${StakingRewardTransfer.getFullName(StakingRewardTransfer.CONSENSUS_TIMESTAMP)}
    from ${StakingRewardTransfer.tableName} ${StakingRewardTransfer.tableAlias}
    where ${StakingRewardTransfer.getFullName(StakingRewardTransfer.ACCOUNT_ID)} = $1`;
```

**File:** importer/src/main/resources/db/migration/v1/V1.65.6__pending_reward.sql (L9-10)
```sql
from entity
where deleted is not true and type in ('ACCOUNT', 'CONTRACT');
```
