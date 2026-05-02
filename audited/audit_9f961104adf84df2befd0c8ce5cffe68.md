### Title
Unauthenticated DB Connection Pool Exhaustion via Concurrent Staking Rewards Queries

### Summary
`listStakingRewardsByAccountId` in `rest/controllers/accountController.js` issues two sequential database queries per request — one for `EntityService.isValidAccount()` and one for `StakingRewardTransferService.getRewards()` — with no application-level rate limiting. The default DB connection pool is capped at 10 connections. An unprivileged attacker with any valid account ID can flood this endpoint at high concurrency, saturating the pool and delaying or blocking legitimate queries across all REST API endpoints that share the same pool.

### Finding Description

**Code path:**

`listStakingRewardsByAccountId` (accountController.js lines 170–203) executes two sequential awaited DB calls per request:

1. `EntityService.isValidAccount(accountId)` — issues `SELECT type FROM entity WHERE id = $1` (entityService.js line 61). This does NOT short-circuit the attack; it adds a second connection acquisition per request.
2. `StakingRewardTransferService.getRewards()` (stakingRewardTransferService.js lines 18–22) — issues:
   ```sql
   SELECT account_id, amount, consensus_timestamp
   FROM staking_reward_transfer srt
   WHERE srt.account_id = $1
   ORDER BY srt.consensus_timestamp DESC
   LIMIT $2
   ```

**Root cause:** Each request holds a pool connection for the duration of each `await`, and there is no per-IP or global request-rate limit enforced at the application layer for the REST API. The `isValidAccount` guard does not prevent the attack — it only requires the attacker to use any existing account ID (trivially available on a public network), and it adds a second DB round-trip per request, worsening pool pressure.

**Pool configuration (default):**
- `maxConnections = 10` (docs line 556, dbpool.js line 14)
- `connectionTimeout = 20000ms` — requests queue for up to 20 seconds waiting for a free connection
- `statementTimeout = 20000ms` — maximum per-query hold time

**Rate limiting gap:** The web3 API has an application-level `ThrottleManager` (bucket4j). The REST API has no equivalent. Traefik middleware (`inFlightReq`, `rateLimit`) is configurable but is not enforced at the application layer and may not be deployed in all environments.

**Why the `isValidAccount` check is insufficient:** It only rejects non-existent accounts. Any of the millions of valid Hedera accounts satisfies it, and it consumes an additional connection slot per request.

### Impact Explanation

With 10 pool connections and two sequential DB queries per request, an attacker sustaining ≥5 concurrent connections to this endpoint can occupy the entire pool. Legitimate requests to any other REST API endpoint sharing the same `global.pool` (dbpool.js lines 36–46) will queue behind the `connectionTimeout` (20 seconds) before failing. This causes measurable latency degradation or 503-equivalent timeouts for all users of the mirror node REST API, constituting a griefing-class availability impact with no economic cost to the attacker.

### Likelihood Explanation

Preconditions are minimal: any valid Hedera account ID (publicly enumerable from the ledger), no credentials, no special network position. The attack is repeatable and scriptable with standard HTTP concurrency tools (e.g., `ab`, `wrk`, `hey`). The only practical mitigations — Traefik middleware and infrastructure-level rate limiting — are optional and deployment-dependent, not enforced in the application code itself.

### Recommendation

1. **Add application-level concurrency/rate limiting** to the REST API analogous to the web3 `ThrottleManager`, enforced per source IP before any DB query is issued.
2. **Increase the default pool size** or configure per-endpoint connection limits so a single endpoint cannot monopolize the shared pool.
3. **Merge the two queries** (`isValidAccount` + `getRewards`) into a single DB round-trip, halving per-request pool pressure.
4. **Set a short `statement_timeout`** specifically for this query class (e.g., 2–3 seconds) rather than the global 20-second default.

### Proof of Concept

```bash
# 1. Obtain any valid account ID (e.g., 0.0.1234) from the public ledger.
# 2. Run 20 concurrent workers, each looping the rewards endpoint:
wrk -t 20 -c 20 -d 30s \
  "https://<mirror-node>/api/v1/accounts/0.0.1234/rewards?limit=100"

# 3. Simultaneously issue a legitimate query to a different endpoint:
curl -w "%{time_total}" \
  "https://<mirror-node>/api/v1/transactions?limit=1"

# Expected result: the legitimate query latency rises to near connectionTimeout
# (up to 20 seconds) or returns a 503/timeout while the pool is saturated.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/service/stakingRewardTransferService.js (L11-22)
```javascript
  static listStakingRewardsByAccountIdQuery = `
    select ${StakingRewardTransfer.getFullName(StakingRewardTransfer.ACCOUNT_ID)},
    ${StakingRewardTransfer.getFullName(StakingRewardTransfer.AMOUNT)},
    ${StakingRewardTransfer.getFullName(StakingRewardTransfer.CONSENSUS_TIMESTAMP)}
    from ${StakingRewardTransfer.tableName} ${StakingRewardTransfer.tableAlias}
    where ${StakingRewardTransfer.getFullName(StakingRewardTransfer.ACCOUNT_ID)} = $1`;

  async getRewards(order, limit, conditions, initParams) {
    const {query, params} = this.getRewardsQuery(order, limit, conditions, initParams);
    const rows = await super.getRows(query, params);
    return rows.map((srt) => new StakingRewardTransfer(srt));
  }
```

**File:** rest/service/entityService.js (L28-63)
```javascript
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;

  static missingAccountAlias = 'No account with a matching alias found';
  static multipleAliasMatch = `Multiple alive entities matching alias`;
  static multipleEvmAddressMatch = `Multiple alive entities matching evm address`;

  /**
   * Retrieves the entity containing matching the given alias
   *
   * @param {AccountAlias} accountAlias accountAlias
   * @return {Promise<Entity>} raw entity object
   */
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);

    if (isEmpty(rows)) {
      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching alias ${accountAlias}`);
      throw new Error(EntityService.multipleAliasMatch);
    }

    return new Entity(rows[0]);
  }

  /**
   * Checks if provided accountId maps to a valid entity
   * @param {BigInt|Number} accountId
   * @returns {Promise<Boolean>} valid flag
   */
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```
