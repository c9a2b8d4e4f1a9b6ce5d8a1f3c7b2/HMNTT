### Title
Missing `deleted` Filter in `isValidAccount()` Allows Stale Reward Data Return for Deleted Accounts

### Summary
`EntityService.isValidAccount()` uses `entityExistenceQuery` which queries the `entity` table by `id` only, with no check on the `deleted` column. This means any account that has been soft-deleted (row still present with `deleted=true`) passes the validity gate in `listStakingRewardsByAccountId()`, causing `StakingRewardTransferService.getRewards()` to execute and return historical reward data for a deleted account instead of a `404`. No network partition is required — the flaw exists unconditionally in the primary code path.

### Finding Description

**Exact code path:**

`rest/controllers/accountController.js`, `listStakingRewardsByAccountId()`, lines 170–185: [1](#0-0) 

The guard at line 172–175 calls `EntityService.isValidAccount(accountId)`: [2](#0-1) 

`isValidAccount()` in `rest/service/entityService.js` lines 60–63 uses `entityExistenceQuery`: [3](#0-2) 

`entityExistenceQuery` is defined at lines 28–30: [4](#0-3) 

```sql
select type from entity where id = $1
```

**Root cause:** There is no `deleted <> true` predicate. The entity row for a deleted account remains in the table with `deleted = true`; the query still returns a row; `!isNil(entity)` evaluates to `true`; the guard passes.

**Contrast with sibling queries in the same file** that correctly filter deleted accounts: [5](#0-4) 

`entityFromAliasQuery` uses `coalesce(deleted, false) <> true` and `entityFromEvmAddressQuery` uses `deleted <> true`. `entityExistenceQuery` has neither.

After the guard passes, `StakingRewardTransferService.getRewards()` executes: [6](#0-5) 

which queries `staking_reward_transfer` filtered only by `account_id = $1` — no deletion check there either. [7](#0-6) 

### Impact Explanation
Any unprivileged caller can send `GET /api/v1/accounts/{deleted_account_id}/rewards` and receive a `200 OK` with the full historical staking reward transfer list for a deleted account, instead of the correct `404 Not Found`. While the staking reward data is public ledger data (not a confidentiality breach), the API contract is violated: deleted accounts are presented as active, and consumers relying on `404` to detect account deletion (e.g., downstream integrations, wallets, monitoring tools) will receive incorrect signals. In a deployment where `config.db.primaryHost` is set and `global.pool` points to a read replica (`rest/dbpool.js` lines 39–46), replication lag amplifies the window during which this incorrect `200` is returned after deletion. [8](#0-7) 

### Likelihood Explanation
Exploitation requires zero privileges — only knowledge of a previously valid account ID (trivially obtainable from public ledger history). The attacker does not need to induce a network partition; the bug fires on every request for any soft-deleted account on the primary DB itself. It is fully repeatable and requires no special timing or race condition.

### Recommendation
Add the `deleted` filter to `entityExistenceQuery` in `rest/service/entityService.js`:

```sql
select type
from entity
where id = $1
  and coalesce(deleted, false) <> true
```

This aligns it with `entityFromAliasQuery` and `entityFromEvmAddressQuery` in the same file. [9](#0-8) 

### Proof of Concept

1. Identify any account that has been deleted on the Hedera network (e.g., `0.0.XXXXX`).
2. Confirm the account is deleted via the primary DB: `SELECT id, deleted FROM entity WHERE id = <encoded_id>;` → `deleted = true`.
3. Send: `GET /api/v1/accounts/0.0.XXXXX/rewards`
4. **Expected:** `404 Not Found`
5. **Actual:** `200 OK` with a JSON body containing `rewards: [...]` (historical staking reward transfers for the deleted account).

No authentication, no special headers, no network manipulation required.

### Citations

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

**File:** rest/service/entityService.js (L17-30)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;

  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;

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

**File:** rest/service/stakingRewardTransferService.js (L18-22)
```javascript
  async getRewards(order, limit, conditions, initParams) {
    const {query, params} = this.getRewardsQuery(order, limit, conditions, initParams);
    const rows = await super.getRows(query, params);
    return rows.map((srt) => new StakingRewardTransfer(srt));
  }
```

**File:** rest/dbpool.js (L39-46)
```javascript
  if (config.db.primaryHost) {
    const primaryPoolConfig = {...poolConfig};
    primaryPoolConfig.host = config.db.primaryHost;
    global.primaryPool = new Pool(primaryPoolConfig);
    handlePoolError(global.primaryPool);
  } else {
    global.primaryPool = pool;
  }
```
