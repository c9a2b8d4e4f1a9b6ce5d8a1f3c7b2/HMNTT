### Title
Unauthenticated Pagination Loop Causes O(N) DB Queries with No Rate Limiting in `listStakingRewardsByAccountId`

### Summary
The `/api/v1/accounts/{id}/rewards` endpoint has no application-level rate limiting and issues two DB queries per HTTP request (one for `isValidAccount`, one for `getRewards`). Because each paginated response carries a unique cursor URL, the Redis response cache never serves a hit for any page beyond the first. An unprivileged attacker can follow the `next` link in a tight loop with `limit=1`, forcing O(N) sequential DB round-trips against the `staking_reward_transfer` table for an account with N rewards, exhausting the small default connection pool and degrading service for all users.

### Finding Description

**Code path:**

`listStakingRewardsByAccountId` in `rest/controllers/accountController.js` lines 170–203:

```
170: listStakingRewardsByAccountId = async (req, res) => {
171:   const accountId = await EntityService.getEncodedId(...);
172:   const isValidAccount = await EntityService.isValidAccount(accountId);  // DB query #1
...
180:   const stakingRewardsTransfers = await StakingRewardTransferService.getRewards(...); // DB query #2
...
194:   if (response.rewards.length === query.limit) {
195:     const lastRow = last(response.rewards);
199:     response.links.next = utils.getPaginationLink(req, false, lastValue, query.order);
200:   }
``` [1](#0-0) 

**Root cause 1 — No rate limiting in the REST server.** The middleware stack in `rest/server.js` contains: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, and optionally `responseCacheCheckHandler`. There is no rate-limiting or in-flight-request-limiting middleware anywhere in the chain. [2](#0-1) 

The rate-limiting code found in the codebase (`ThrottleConfiguration.java`, `ThrottleManagerImpl.java`) belongs exclusively to the `web3` Java service and does not apply to the Node.js REST server.

**Root cause 2 — Cache bypass via unique cursor URLs.** The response cache key is `MD5(req.originalUrl)`:

```js
const cacheKeyGenerator = (req) =>
  crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
``` [3](#0-2) 

Each paginated `next` link embeds a new `timestamp=gt:{cursor}` value, producing a unique URL per page. Every page request is therefore a cache miss and hits the database.

**Root cause 3 — `isValidAccount` called on every paginated request.** The account validity check at line 172 issues a separate DB query on every single request, including every follow-on pagination request for the same account. This doubles the DB load per page. [4](#0-3) 

**Root cause 4 — No timestamp range restriction on the rewards endpoint.** The `extractStakingRewardsQuery` function accepts an unbounded `gte:1` timestamp filter with no `maxTimestampRange` enforcement (the 7-day range guard documented in configuration is not applied here). [5](#0-4) 

**DB pool constraints:** The default pool is only 10 connections with a 20-second statement timeout. [6](#0-5) [7](#0-6) 

### Impact Explanation

Each page request consumes 2 DB connections from a pool of 10 (default). With `limit=1` and N staking rewards, an attacker issues N HTTP requests causing 2N DB queries. Multiple concurrent attackers (or a single attacker with concurrent connections) can saturate the 10-connection pool, causing legitimate requests across all endpoints to queue or time out. The `staking_reward_transfer` table is queried with `WHERE account_id = $1 AND consensus_timestamp > $3 ORDER BY consensus_timestamp ASC LIMIT $2`, which is an indexed range scan — each query is cheap individually, but the aggregate sustained load from a tight loop is the threat. [8](#0-7) 

### Likelihood Explanation

No privileges are required. Any internet-accessible deployment is reachable. The attack requires only knowledge of one account ID with many staking rewards (publicly observable on-chain). The `next` link is machine-readable and trivially scriptable. The minimum viable attack is a single `curl` loop or a simple Python script. Multiple attackers can coordinate to amplify pool exhaustion.

### Recommendation

1. **Add rate limiting middleware** to the Node.js REST server (e.g., `express-rate-limit`) applied globally or specifically to the `/accounts/:id/rewards` route.
2. **Cache the `isValidAccount` result** in memory (keyed by `accountId`) for the lifetime of a request session, or move the check outside the per-page hot path. The account does not change between paginated requests.
3. **Enforce a minimum `limit` floor** (e.g., reject `limit=1` or enforce `limit >= 10`) to reduce the number of round-trips an attacker can force.
4. **Apply `maxTimestampRange`** to the rewards endpoint to bound the scan window, consistent with other timestamp-filtered endpoints.

### Proof of Concept

```bash
# Step 1: Get first page with limit=1 from epoch start
NEXT="/api/v1/accounts/0.0.1234/rewards?timestamp=gte:1&order=asc&limit=1"

# Step 2: Follow next links in a tight loop
while [ "$NEXT" != "null" ]; do
  RESPONSE=$(curl -s "https://<mirror-node-host>${NEXT}")
  NEXT=$(echo "$RESPONSE" | jq -r '.links.next')
  # Each iteration: 2 DB queries (isValidAccount + getRewards)
  # Each URL is unique (timestamp=gt:<cursor>) → cache miss every time
done
# For an account with N rewards: N HTTP requests, 2N DB queries, no rate limiting applied
```

With 10 concurrent instances of this loop targeting the same or different accounts, the default 10-connection DB pool is fully saturated, causing `connectionTimeoutMillis` (20s) errors for all other API consumers.

### Citations

**File:** rest/controllers/accountController.js (L110-162)
```javascript
  extractStakingRewardsQuery(filters) {
    let limit = defaultLimit;
    let order = orderFilterValues.DESC;
    const timestampInValues = [];
    const conditions = [];
    const params = [];
    const startPosition = 3; // caller will later insert accountId at $1 and limit at $2

    for (const filter of filters) {
      if (isNil(filter)) {
        continue;
      }

      switch (filter.key) {
        case filterKeys.LIMIT:
          limit = filter.value;
          break;
        case filterKeys.ORDER:
          order = filter.value;
          break;
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
        default:
          break;
      }
    }

    this.updateQueryFiltersWithInValues(
      params,
      conditions,
      timestampInValues,
      StakingRewardTransfer.getFullName(StakingRewardTransfer.CONSENSUS_TIMESTAMP),
      startPosition + params.length
    );

    return {
      order,
      limit,
      conditions,
      params,
    };
  }
```

**File:** rest/controllers/accountController.js (L170-203)
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
    const rewards = stakingRewardsTransfers.map((reward) => new StakingRewardTransferViewModel(reward));
    const response = {
      rewards,
      links: {
        next: null,
      },
    };

    if (response.rewards.length === query.limit) {
      const lastRow = last(response.rewards);
      const lastValue = {
        [filterKeys.TIMESTAMP]: lastRow.timestamp,
      };
      response.links.next = utils.getPaginationLink(req, false, lastValue, query.order);
    }

    res.locals[responseDataLabel] = response;
  };
```

**File:** rest/server.js (L67-98)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** rest/service/stakingRewardTransferService.js (L11-35)
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

  getRewardsQuery(order, limit, conditions, params) {
    const query = [
      StakingRewardTransferService.listStakingRewardsByAccountIdQuery,
      conditions.length > 0 ? `and ${conditions.join(' and ')}` : '', // "and" since we already have "where account_id = $1" at the end of the above line
      super.getOrderByQuery(
        OrderSpec.from(StakingRewardTransfer.getFullName(StakingRewardTransfer.CONSENSUS_TIMESTAMP), order)
      ),
      super.getLimitQuery(2), // limit is specified in $2 (not necessarily a limit *of* 2)
    ].join('\n');

    return {query, params};
  }
```
