Looking at the actual code carefully across `rest/controllers/accountController.js`, `rest/service/entityService.js`, and `rest/service/stakingRewardTransferService.js`.

**Key finding — `entityExistenceQuery` has no `deleted` filter:** [1](#0-0) 

```sql
select type from entity where id = $1
```

Compare with the other queries in the same file that explicitly exclude deleted accounts: [2](#0-1) 

`entityFromAliasQuery` uses `coalesce(deleted, false) <> true` and `entityFromEvmAddressQuery` uses `deleted <> true`, but `entityExistenceQuery` — used by `isValidAccount` — has **no deleted filter at all**. [3](#0-2) 

The staking rewards query also has no deletion guard: [4](#0-3) 

The timestamp filter is passed through directly from user input with no deletion-aware bounds: [5](#0-4) 

---

### Title
Deleted Account Staking Rewards Exposed via Missing `deleted` Filter in `isValidAccount`

### Summary
`EntityService.isValidAccount()` uses `entityExistenceQuery` which queries `entity` by `id` only, with no filter on the `deleted` column. This allows deleted accounts to pass the existence gate in `listStakingRewardsByAccountId`. Combined with user-controlled `timestamp=lte:X` filtering, any unauthenticated caller can retrieve historical staking rewards for a deleted account.

### Finding Description
In `rest/service/entityService.js` lines 28–30, `entityExistenceQuery` is:
```sql
select type from entity where id = $1
```
No `deleted` predicate. `isValidAccount()` (lines 60–63) returns `true` for any row found, including rows where `deleted = true`. The other two queries in the same class (`entityFromAliasQuery`, `entityFromEvmAddressQuery`) both explicitly exclude deleted entities, making this an inconsistency.

In `listStakingRewardsByAccountId` (lines 170–175 of `accountController.js`), the only guard is:
```js
const isValidAccount = await EntityService.isValidAccount(accountId);
if (!isValidAccount) throw new NotFoundError();
```
Since this passes for deleted accounts, execution continues. The `extractStakingRewardsQuery` method (lines 110–162) accepts any `timestamp` operator except `ne`, including `lte`, and passes it directly into the SQL WHERE clause. `StakingRewardTransferService.listStakingRewardsByAccountIdQuery` (lines 11–16) has no deletion check either. The final query becomes:
```sql
select srt.account_id, srt.amount, srt.consensus_timestamp
from staking_reward_transfer srt
where srt.account_id = $1
  and srt.consensus_timestamp <= <attacker_value>
order by srt.consensus_timestamp desc limit $2
```

### Impact Explanation
An unprivileged external user can enumerate historical staking rewards for any deleted account by supplying its numeric ID (which remains in the `entity` table with `deleted = true`) and a `timestamp=lte:X` filter. This exposes the full pre-deletion staking history of accounts whose owners may have expected deletion to sever access. Severity: Medium — information disclosure of historical financial activity on a public ledger, but the data is not cryptographically private.

### Likelihood Explanation
No authentication is required. The account numeric ID is publicly observable from the ledger. The `deleted` flag does not purge the entity row. Any attacker who knows (or can enumerate) a deleted account's numeric ID can trigger this. Fully repeatable with a single HTTP GET request.

### Recommendation
Add a `deleted` filter to `entityExistenceQuery` in `rest/service/entityService.js`:
```js
static entityExistenceQuery = `select ${Entity.TYPE}
                               from ${Entity.tableName}
                               where ${Entity.ID} = $1
                                 and coalesce(${Entity.DELETED}, false) <> true`;
```
This aligns it with the pattern already used by `entityFromAliasQuery`. Alternatively, if historical data for deleted accounts is intentionally accessible, document that explicitly and rename `isValidAccount` to `accountExists` to avoid the misleading implication that deleted accounts are invalid.

### Proof of Concept
1. Identify a deleted account, e.g. `0.0.1001` (entity row exists with `deleted = true`, deletion consensus timestamp `T_del`).
2. Send: `GET /api/v1/accounts/0.0.1001/rewards?timestamp=lte:<T_del - 1>`
3. Observe: HTTP 200 with full list of staking rewards that predate the deletion event, rather than HTTP 404.
4. Root cause confirmed: `isValidAccount` returns `true` because `entityExistenceQuery` has no `deleted` predicate, and the staking rewards query applies the user-supplied timestamp filter without any deletion-aware bound.

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

**File:** rest/service/stakingRewardTransferService.js (L11-16)
```javascript
  static listStakingRewardsByAccountIdQuery = `
    select ${StakingRewardTransfer.getFullName(StakingRewardTransfer.ACCOUNT_ID)},
    ${StakingRewardTransfer.getFullName(StakingRewardTransfer.AMOUNT)},
    ${StakingRewardTransfer.getFullName(StakingRewardTransfer.CONSENSUS_TIMESTAMP)}
    from ${StakingRewardTransfer.tableName} ${StakingRewardTransfer.tableAlias}
    where ${StakingRewardTransfer.getFullName(StakingRewardTransfer.ACCOUNT_ID)} = $1`;
```

**File:** rest/controllers/accountController.js (L130-142)
```javascript
        case filterKeys.TIMESTAMP:
          if (utils.opsMap.ne === filter.operator) {
            throw new InvalidArgumentError(`Not equals (ne) operator is not supported for ${filterKeys.TIMESTAMP}`);
          }
          this.updateConditionsAndParamsWithInValues(
            filter,
            timestampInValues,
            params,
            conditions,
            StakingRewardTransfer.getFullName(StakingRewardTransfer.CONSENSUS_TIMESTAMP),
            startPosition + params.length
          );
          break;
```
