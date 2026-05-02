### Title
Unauthenticated Resource Exhaustion via Broad `account.balance=gte:0` Query with No Timestamp Filter in `getBalances()`

### Summary
The `getBalances()` handler in `rest/balances.js` contains a no-timestamp code path that builds a query scanning the entire `entity` table (filtered only by type) and executes a correlated `token_account` subquery for each returned row. Because the REST API has no per-IP rate limiting, any unauthenticated caller can repeatedly issue `GET /api/v1/balances?account.balance=gte:0&limit=100` to drive sustained, high-cost DB work, degrading service for all users.

### Finding Description

**Exact code path:**

The no-timestamp branch in `getBalances()` at `rest/balances.js` lines 133–149:

```js
} else {
  const conditions = [accountQuery, pubKeyQuery, balanceQuery].filter(Boolean).join(' and ');
  const whereClause = conditions && `where ${conditions}`;
  const tokenBalanceSubQuery = getTokenAccountBalanceSubQuery(order);
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
``` [1](#0-0) 

The correlated subquery at lines 308–318:

```js
const getTokenAccountBalanceSubQuery = (order) => {
  return `
    select json_agg(json_build_object('token_id', token_id, 'balance', balance))
    from (
      select token_id, balance
      from token_account ta
      where ta.account_id = ab.account_id and ta.associated is true
      order by token_id ${order}
      limit ${tokenBalanceLimit.multipleAccounts}
    ) as account_token_balance`;
};
``` [2](#0-1) 

**Root cause and failed assumption:**

The `account.balance` filter passes validation because `filterValidityChecks` accepts `gte:0` (`isPositiveLong(val, true)` allows zero): [3](#0-2) 

The `entity_balance` CTE has no `LIMIT` of its own. The outer `LIMIT` (capped at 100) is applied after the CTE, meaning the DB must evaluate the full `entity` table scan filtered by type before applying the row limit. For each of the up to 100 returned rows, a separate correlated lookup into `token_account` is executed (up to 50 rows each).

The REST API server registers no per-IP or per-request rate-limiting middleware: [4](#0-3) 

The only throttling present in the codebase is in the `web3` Java module (`ThrottleConfiguration`, `ThrottleManagerImpl`), which is entirely separate from the Node.js REST API: [5](#0-4) 

The `authHandler` middleware only adjusts the response `limit` ceiling for authenticated users — it is not a rate limiter: [6](#0-5) 

**Why existing checks fail:**

- `getLimitParamValue` caps the limit at `responseLimit.max` (default 100), which bounds per-request output but does not bound request frequency.
- The DB pool `statementTimeout` provides a per-query wall-clock ceiling but does not prevent many concurrent queries from saturating I/O simultaneously.
- The `balanceFilterValidator` correctly accepts `gte:0` as a valid filter — there is no semantic check rejecting "match-all" balance predicates. [7](#0-6) 

### Impact Explanation

Each request with `account.balance=gte:0` and no timestamp causes:
1. A full scan of the `entity` table (potentially millions of rows on mainnet) filtered by type.
2. Up to 100 correlated `token_account` lookups (up to 50 rows each = up to 5,000 index lookups per request).

At scale (e.g., 50–100 concurrent attackers each sending requests in a tight loop), this saturates DB read I/O and connection pool slots, causing query latency to spike for all legitimate users. No funds are at risk; the impact is availability degradation (griefing).

### Likelihood Explanation

- **Precondition**: None. No account, API key, or authentication is required.
- **Trigger**: A single HTTP GET with two query parameters.
- **Repeatability**: Trivially scriptable with `curl` or any HTTP client in a loop.
- **Distributed amplification**: Multiple IPs can coordinate without any on-chain cost.
- **Detection evasion**: Each individual request is valid and returns HTTP 200; no anomaly is raised at the application layer.

### Recommendation

1. **Add per-IP rate limiting** to the REST API middleware stack (e.g., `express-rate-limit` or an upstream reverse-proxy rule) before route handlers are invoked.
2. **Add a LIMIT to the `entity_balance` CTE** itself (or rewrite it as a direct query with `LIMIT` pushed down) so the DB planner can stop scanning early.
3. **Require a timestamp filter** for broad balance queries (i.e., reject requests with no `timestamp` and no selective `account.id` filter), or add a minimum selectivity requirement.
4. **Set a tighter `statementTimeout`** for the REST DB pool to bound the worst-case duration of any single query.

### Proof of Concept

```bash
# Single maximally-broad request (no timestamp, balance matches all accounts, max limit)
curl "https://<mirror-node>/api/v1/balances?account.balance=gte:0&limit=100"

# Sustained flood from a single attacker (no privileges required)
while true; do
  curl -s "https://<mirror-node>/api/v1/balances?account.balance=gte:0&limit=100" > /dev/null &
done

# Distributed variant: run the above loop from N machines simultaneously
# Each request triggers: full entity table scan + up to 100 correlated token_account lookups
# No authentication, no API key, no on-chain cost
```

Expected result: DB CPU and I/O utilization climbs proportionally with request rate; legitimate queries (transactions, accounts, etc.) experience increased latency or timeouts as the DB connection pool is exhausted.

### Citations

**File:** rest/balances.js (L133-149)
```javascript
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
```

**File:** rest/balances.js (L308-318)
```javascript
const getTokenAccountBalanceSubQuery = (order) => {
  return `
    select json_agg(json_build_object('token_id', token_id, 'balance', balance))
    from (
      select token_id, balance
      from token_account ta
      where ta.account_id = ab.account_id and ta.associated is true
      order by token_id ${order}
      limit ${tokenBalanceLimit.multipleAccounts}
    ) as account_token_balance`;
};
```

**File:** rest/balances.js (L359-363)
```javascript
const balanceFilterValidator = (param, op, val) => {
  return param === constants.filterKeys.ACCOUNT_ID
    ? utils.validateOpAndValue(op, val)
    : utils.filterValidityChecks(param, op, val);
};
```

**File:** rest/utils.js (L286-288)
```javascript
    case constants.filterKeys.ACCOUNT_BALANCE:
      ret = isPositiveLong(val, true);
      break;
```

**File:** rest/utils.js (L533-536)
```javascript
const getEffectiveMaxLimit = () => {
  const userLimit = httpContext.get(userLimitLabel);
  return userLimit !== undefined ? userLimit : responseLimit.max;
};
```

**File:** rest/server.js (L67-99)
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
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
```
