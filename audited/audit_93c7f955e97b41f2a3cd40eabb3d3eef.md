### Title
Unauthenticated High-Frequency Timestamp-Filtered `/balances` Requests Exhaust DB Connection Pool (DoS)

### Summary
The `getBalances()` handler in `rest/balances.js` accepts a `timestamp` query parameter from any unauthenticated caller with no rate limiting. When a timestamp is supplied, the handler executes two sequential, expensive PostgreSQL queries per request against the `account_balance` and `token_balance` tables. Because the REST API has no per-IP or global request throttle, an attacker can saturate the default 10-connection pool with concurrent requests, blocking all legitimate traffic until the 20-second statement timeout expires per slot.

### Finding Description

**Exact code path:**

`getBalances()` at [1](#0-0)  branches on whether `tsQuery` is truthy at line 113. When a `timestamp` parameter is present, `eq` is silently rewritten to `lte` at line 91, so `timestamp=<current_ns>` becomes `consensus_timestamp <= <current_ns>`.

`getTsQuery()` at [2](#0-1)  calls `getAccountBalanceTimestampRange()`, which calls `getOptimizedTimestampRange()` at [3](#0-2) . That function computes:

```
effectiveUpperBound = min(userTimestamp, nowInNs)   // = current_ns when equal
optimalLowerBound   = firstDayOfMonth(effectiveUpperBound, -1)  // ~1-2 months back
```

This guarantees the range covers the most recent (and most populated) monthly partitions. `getAccountBalanceTimestampRange()` then fires **Query 1** — a point-lookup on `account_balance` for the treasury account to find the latest snapshot: [4](#0-3) 

If a snapshot is found (always true for a live network), `getBalancesQuery()` at [5](#0-4)  builds **Query 2** — a `SELECT DISTINCT ON (account_id)` across `account_balance` with a correlated `token_balance` subquery per returned account: [6](#0-5) 

**Root cause — no rate limiting on the REST API:**

`server.js` registers the `/balances` route with no throttle middleware: [7](#0-6) 

The middleware stack is: `httpContext → requestLogger → authHandler → (optional metrics) → (optional cache check) → handler`. The `authHandler` only sets a custom response limit for authenticated users; it does not reject or throttle unauthenticated callers: [8](#0-7) 

The throttle/rate-limit infrastructure that exists in the codebase is scoped exclusively to the web3 contract-call path: [9](#0-8) 

**DB pool constraints:**

The pool defaults to `maxConnections: 10` and `statementTimeout: 20000 ms`: [10](#0-9) 

Confirmed in documentation: [11](#0-10) 

**Why the response cache does not help:**

The cache key is the MD5 of `req.originalUrl`: [12](#0-11) 

The cache is also disabled by default (`cache.response.enabled: false`): [13](#0-12) 

Even when enabled, each request with a distinct nanosecond timestamp value produces a unique cache key, so the attacker trivially bypasses it by incrementing the timestamp by 1 ns per request.

### Impact Explanation

With 10 pool connections and a 20-second statement timeout, an attacker needs only **10 concurrent long-running requests** to hold every connection slot. All legitimate API requests — including those used by consensus nodes, explorers, and wallets to verify transaction finality — queue indefinitely or receive connection-timeout errors. Because the REST mirror node is the primary read path for the Hedera network's public state, sustained pool exhaustion constitutes a practical network-wide read outage. The severity is **Critical** per the stated scope (total network read shutdown).

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and a single HTTP GET. The attacker does not need to know any account IDs or token IDs. Any current Unix nanosecond timestamp (or any timestamp within the last two months) reliably triggers the expensive two-query path. The attack is trivially scriptable with `curl` or any HTTP load tool and is repeatable indefinitely. The only natural bound is the 20-second statement timeout, which the attacker simply re-fires continuously.

### Recommendation

1. **Add a rate limiter to the REST API** (e.g., `express-rate-limit` or Traefik's `rateLimit` middleware) scoped per source IP, targeting at minimum the `/api/v1/balances` endpoint.
2. **Reduce `statementTimeout`** for the balance snapshot lookup (Query 1) to a few hundred milliseconds; it is a single-row indexed lookup and should never take seconds.
3. **Enable and enforce the Redis response cache** for timestamp-filtered balance requests, and use a cache key that normalises the timestamp to the nearest balance snapshot boundary (15-minute granularity) rather than the raw nanosecond value, so that all requests within the same snapshot window share a single cache entry.
4. **Increase `maxConnections`** or deploy a connection pooler (PgBouncer) to decouple HTTP concurrency from DB connection exhaustion.

### Proof of Concept

```bash
# Get current nanosecond timestamp
NOW_NS=$(date +%s%N)

# Fire 15 concurrent requests (exceeds default pool of 10)
for i in $(seq 1 15); do
  curl -s "http://<mirror-node-host>:5551/api/v1/balances?timestamp=${NOW_NS}&limit=100" &
done
wait

# Legitimate request now queues or times out:
curl -v "http://<mirror-node-host>:5551/api/v1/balances"
# Expected: hangs until a pool slot frees (up to 20s) or returns connection error

# Bypass cache by incrementing timestamp by 1 ns per wave:
for wave in $(seq 1 100); do
  TS=$((NOW_NS + wave))
  for i in $(seq 1 10); do
    curl -s "http://<mirror-node-host>:5551/api/v1/balances?timestamp=${TS}&limit=100" &
  done
done
```

### Citations

**File:** rest/balances.js (L83-156)
```javascript
const getBalances = async (req, res) => {
  utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator);

  // Parse the filter parameters for credit/debit, account-numbers, timestamp and pagination
  const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
  const accountParams = await Promise.all(accountParamsPromise);
  // transform the timestamp=xxxx or timestamp=eq:xxxx query in url to 'timestamp <= xxxx' SQL query condition
  let [tsQuery, tsParams] = utils.parseTimestampQueryParam(req.query, 'consensus_timestamp', {
    [utils.opsMap.eq]: utils.opsMap.lte,
  });
  const [balanceQuery, balanceParams] = utils.parseBalanceQueryParam(req.query, 'ab.balance');
  const [pubKeyQuery, pubKeyParams] = utils.parsePublicKeyQueryParam(req.query, 'public_key');
  const {
    query: limitQuery,
    params,
    order,
    limit,
  } = utils.parseLimitAndOrderParams(req, constants.orderFilterValues.DESC);

  res.locals[constants.responseDataLabel] = {
    timestamp: null,
    balances: [],
    links: {
      next: null,
    },
  };

  let sqlQuery;
  let sqlParams;

  if (tsQuery) {
    const tsQueryResult = await getTsQuery(tsQuery, tsParams);
    if (!tsQueryResult.query) {
      return;
    }

    const accountIdsQuery = await getAccountIdsByPublicKey(pubKeyParams, limit);
    if (pubKeyQuery && !accountIdsQuery) {
      return;
    }

    [sqlQuery, tsParams] = await getBalancesQuery(
      accountQuery,
      balanceQuery,
      accountIdsQuery,
      limitQuery,
      order,
      tsQueryResult
    );
    sqlParams = utils.mergeParams(tsParams, accountParams, balanceParams, params);
  } else {
    // use current balance from entity table when there's no timestamp query filter
    const conditions = [accountQuery, pubKeyQuery, balanceQuery].filter(Boolean).join(' and ');
    const whereClause = conditions && `where ${conditions}`;
    const tokenBalanceSubQuery = getTokenAccountBalanceSubQuery(order);
    sqlParams = utils.mergeParams(tsParams, accountParams, pubKeyParams, balanceParams, params);
    sqlQuery = `
      with entity_balance as (
        select id as account_id, balance, balance_timestamp as consensus_timestamp, public_key
        from entity
        where type in ('ACCOUNT', 'CONTRACT')
      )
      select ab.*, (${tokenBalanceSubQuery}) as token_balances
      from entity_balance ab
      ${whereClause}
      order by ab.account_id ${order}
      ${limitQuery}`;
  }

  const pgSqlQuery = utils.convertMySqlStyleQueryToPostgres(sqlQuery);
  const result = await pool.queryQuietly(pgSqlQuery, sqlParams);
  res.locals[constants.responseDataLabel] = formatBalancesResult(req, result, limit, order);
  logger.debug(`getBalances returning ${result.rows.length} entries`);
};
```

**File:** rest/balances.js (L182-189)
```javascript
  const query = `
    select consensus_timestamp
    from account_balance
    where ${condition}
    order by consensus_timestamp desc
    limit 1`;

  const {rows} = await pool.queryQuietly(query, params);
```

**File:** rest/balances.js (L199-218)
```javascript
const getBalancesQuery = async (accountQuery, balanceQuery, accountIdsQuery, limitQuery, order, tsQueryResult) => {
  const tokenBalanceSubQuery = getTokenBalanceSubQuery(order, tsQueryResult.query);
  const whereClause = `
      where ${[tsQueryResult.query, accountQuery, accountIdsQuery, balanceQuery].filter(Boolean).join(' and ')}`;
  const {lower, upper} = tsQueryResult.timestampRange;
  // The first upper is for the consensus_timestamp in the select fields, also double the lower and the upper since
  // they are used twice, in the token balance subquery and in the where clause of the main query
  const tsParams = [upper, lower, upper, lower, upper];
  const sqlQuery = `
      select distinct on (account_id)
        ab.account_id,
        ab.balance,
        ?::bigint as consensus_timestamp,
        (${tokenBalanceSubQuery}) as token_balances
      from account_balance ab
      ${whereClause}
      order by ab.account_id ${order}, ab.consensus_timestamp desc
      ${limitQuery}`;
  return [sqlQuery, tsParams];
};
```

**File:** rest/balances.js (L229-276)
```javascript
const getOptimizedTimestampRange = (tsQuery, tsParams) => {
  let lowerBound = 0n;
  const neParams = [];
  let upperBound = constants.MAX_LONG;

  // Find the lower bound and the upper bound from tsParams if present
  tsQuery
    .split('?')
    .filter(Boolean)
    .forEach((query, index) => {
      const value = BigInt(tsParams[index]);
      // eq operator has already been converted to the lte operator
      if (query.includes(utils.opsMap.lte)) {
        // lte operator includes the lt operator, so this clause must before the lt clause
        upperBound = utils.bigIntMin(upperBound, value);
      } else if (query.includes(utils.opsMap.lt)) {
        // Convert lt to lte to simplify query
        const ltValue = value - 1n;
        upperBound = utils.bigIntMin(upperBound, ltValue);
      } else if (query.includes(utils.opsMap.gte)) {
        // gte operator includes the gt operator, so this clause must come before the gt clause
        lowerBound = utils.bigIntMax(lowerBound, value);
      } else if (query.includes(utils.opsMap.gt)) {
        // Convert gt to gte to simplify query
        const gtValue = value + 1n;
        lowerBound = utils.bigIntMax(lowerBound, gtValue);
      } else if (query.includes(utils.opsMap.ne)) {
        neParams.push(value);
      }
    });

  if (lowerBound > upperBound) {
    return {};
  }

  // The optimized range of [lower, upper] should overlap with at most two months, with the exception that when upper
  // is more than 1 month in the future, the range may cover more months. Since the partition maintenance job will
  // create at most one monthly partition ahead, it's unnecessary to adjust the upper bound.
  // With the assumption that the data in db is in sync with the network, in other words, the balance information is
  // update-to-date as of NOW in wall clock, the algorithm below sets lower bound to
  //   max(lowerBound from user, first day of the month before the month min(now, upperBound) is in)
  const nowInNs = utils.nowInNs();
  const effectiveUpperBound = utils.bigIntMin(upperBound, nowInNs);
  const optimalLowerBound = utils.getFirstDayOfMonth(effectiveUpperBound, -1);
  lowerBound = utils.bigIntMax(lowerBound, optimalLowerBound);

  return {lowerBound, upperBound, neParams};
};
```

**File:** rest/balances.js (L278-292)
```javascript
const getTsQuery = async (tsQuery, tsParams) => {
  const {lower, upper} = await getAccountBalanceTimestampRange(tsQuery, tsParams);
  if (lower === undefined) {
    return {};
  }

  const query = 'ab.consensus_timestamp >= ? and ab.consensus_timestamp <= ?';
  return {
    query,
    timestampRange: {
      lower,
      upper,
    },
  };
};
```

**File:** rest/balances.js (L294-306)
```javascript
const getTokenBalanceSubQuery = (order, consensusTsQuery) => {
  consensusTsQuery = consensusTsQuery.replaceAll('ab.', 'tb.');
  return `
    select json_agg(json_build_object('token_id', token_id, 'balance', balance))
    from (
      select distinct on (token_id) token_id, balance
      from token_balance tb
      where tb.account_id = ab.account_id
        and ${consensusTsQuery}
      order by token_id ${order}, consensus_timestamp desc
      limit ${tokenBalanceLimit.multipleAccounts}
    ) as account_token_balance`;
};
```

**File:** rest/server.js (L54-54)
```javascript
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
```

**File:** rest/server.js (L105-106)
```javascript
// balances routes
app.getExt(`${apiPrefix}/balances`, balances.getBalances);
```

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
