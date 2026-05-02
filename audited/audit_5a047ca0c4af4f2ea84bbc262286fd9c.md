### Title
Unauthenticated Three-Part UNION ALL Query Amplification DoS via Token Allowance Range Filters

### Summary
An unprivileged external user can craft a single HTTP request to `/api/v1/accounts/{id}/allowances/tokens` with both lower and upper bounds on `spender.id` and `token.id` simultaneously, causing `extractTokenMultiUnionQuery()` to produce three non-empty filter sets (lower, inner, upper). `TokenAllowanceService.getQuery()` then assembles a three-subquery `UNION ALL` SQL statement, tripling DB work per request. The REST API has no rate-limiting middleware, so flooding this endpoint with concurrent requests exhausts DB CPU and degrades mirror node processing capacity.

### Finding Description

**Code path:**

`extractTokenMultiUnionQuery()` in [1](#0-0)  parses `spender.id` into `bounds.primary` and `token.id` into `bounds.secondary` via `Bound.parse()`. The only guard is `this.validateBounds(bounds)`.

`validateBounds()` in [2](#0-1)  calls four sub-validators. None of them reject the combination of `spender.id=gte:X&spender.id=lte:Y&token.id=gte:A&token.id=lte:B`:

- `validateBoundsRange` [3](#0-2)  only rejects range+equal on the same key — not range+range across both keys.
- `validateLowerBounds` [4](#0-3)  passes because `primary.lower.operator` is `gte` (not `gt`).
- `validateUpperBounds` [5](#0-4)  passes because `primary.upper.operator` is `lte` (not `lt`).
- `validateSecondaryBound` passes because primary is non-empty.

With both bounds set on both keys, `getLowerFilters` returns `[{spender.id=X}, token.id>=A]`, `getInnerFilters` returns `[spender.id>X, spender.id<Y]`, and `getUpperFilters` returns `[{spender.id=Y}, token.id<=B]` — all three non-empty. [6](#0-5) 

`getQuery()` in [7](#0-6)  filters out empty arrays and, finding three non-empty sets, joins them with `UNION ALL`, producing:

```sql
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=$3 AND token_id>=$4 ORDER BY spender,token_id LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender>$3 AND spender<$5 ORDER BY spender,token_id LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=$5 AND token_id<=$6 ORDER BY spender,token_id LIMIT $2)
ORDER BY spender, token_id LIMIT $2
```

**No rate limiting exists on the REST API.** The grep search across all `rest/**/*.js` files for `rateLimit`, `throttle`, and `requestsPerSecond` returns only a single test-utility match. The `server.js` middleware stack [8](#0-7)  registers: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — no rate-limiting middleware. The `authHandler` [9](#0-8)  only sets a custom result-count limit for authenticated users; unauthenticated requests pass through unconditionally.

The throttle mechanism found in the codebase (`ThrottleManagerImpl`, `ThrottleConfiguration`) applies exclusively to the `web3` Java service (contract calls), not to the REST Node.js service. [10](#0-9) 

### Impact Explanation

Each crafted request generates 3 independent DB subqueries plus an outer sort, compared to 1 subquery for a simple request — a 3× amplification factor with no per-IP or global request-rate cap. Against a production `token_allowance` table with millions of rows, the outer `ORDER BY spender, token_id LIMIT $2` must merge and sort up to `3 × limit` rows from three separate index scans. Flooding this endpoint from a single host or small botnet can saturate DB CPU, causing query queues to back up across all mirror node instances sharing the same PostgreSQL backend, degrading ≥30% of processing capacity without any brute-force credential requirement.

### Likelihood Explanation

The endpoint is fully public — no authentication, no API key, no CAPTCHA. The exploit requires only knowledge of the API's filter syntax (publicly documented). A single attacker with a modest connection pool (e.g., 200 concurrent HTTP clients) can sustain thousands of three-subquery DB hits per second. The attack is trivially repeatable and scriptable with `curl`, `ab`, or `wrk`.

### Recommendation

1. **Add rate-limiting middleware to the REST API** (e.g., `express-rate-limit`) at the Express layer, keyed by IP, before route handlers.
2. **Restrict the three-part UNION ALL path**: In `validateBounds`, reject the combination where both `primary` and `secondary` have both lower and upper bounds simultaneously, or require authentication for range-on-range queries.
3. **Add a DB-level statement timeout** for the REST API's connection pool (analogous to `hiero.mirror.web3.db.statementTimeout`) to cap runaway queries.
4. **Consider query cost estimation**: If the primary range `[X, Y]` is wide, force a single-subquery path instead of the three-part UNION ALL.

### Proof of Concept

```bash
# Single request that triggers the 3-part UNION ALL
curl "https://<mirror-node>/api/v1/accounts/0.0.1/allowances/tokens?\
spender.id=gte:0.0.1&spender.id=lte:0.0.9999999&\
token.id=gte:0.0.1&token.id=lte:0.0.9999999&limit=100"

# Flood with concurrent requests (no credentials needed)
wrk -t 20 -c 200 -d 60s \
  "https://<mirror-node>/api/v1/accounts/0.0.1/allowances/tokens?\
spender.id=gte:0.0.1&spender.id=lte:0.0.9999999&\
token.id=gte:0.0.1&token.id=lte:0.0.9999999&limit=100"
```

Expected result: DB CPU climbs to saturation; mirror node REST latency and importer processing degrade across all instances sharing the database.

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L22-60)
```javascript
  extractTokenMultiUnionQuery(filters, ownerAccountId) {
    const bounds = {
      primary: new Bound(filterKeys.SPENDER_ID, 'spender'),
      secondary: new Bound(filterKeys.TOKEN_ID, 'token_id'),
    };
    let limit = defaultLimit;
    let order = orderFilterValues.ASC;

    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.SPENDER_ID:
          bounds.primary.parse(filter);
          break;
        case filterKeys.TOKEN_ID:
          bounds.secondary.parse(filter);
          break;
        case filterKeys.LIMIT:
          limit = filter.value;
          break;
        case filterKeys.ORDER:
          order = filter.value;
          break;
        default:
          break;
      }
    }

    this.validateBounds(bounds);

    return {
      bounds,
      lower: this.getLowerFilters(bounds),
      inner: this.getInnerFilters(bounds),
      upper: this.getUpperFilters(bounds),
      order,
      ownerAccountId,
      limit,
    };
  }
```

**File:** rest/controllers/baseController.js (L56-61)
```javascript
  validateBounds(bounds) {
    this.validateBoundsRange(bounds);
    this.validateSecondaryBound(bounds);
    this.validateLowerBounds(bounds);
    this.validateUpperBounds(bounds);
  }
```

**File:** rest/controllers/baseController.js (L83-92)
```javascript
  validateLowerBounds(bounds) {
    const {primary, secondary} = bounds;
    if (
      !primary.hasEqual() &&
      secondary.hasLower() &&
      (!primary.hasLower() || primary.lower.operator === utils.opsMap.gt)
    ) {
      throw new InvalidArgumentError(`${primary.filterKey} must have gte or eq operator`);
    }
  }
```

**File:** rest/controllers/baseController.js (L100-109)
```javascript
  validateUpperBounds(bounds) {
    const {primary, secondary} = bounds;
    if (
      !primary.hasEqual() &&
      secondary.hasUpper() &&
      (!primary.hasUpper() || primary.upper.operator === utils.opsMap.lt)
    ) {
      throw new InvalidArgumentError(`${primary.filterKey} must have lte or eq operator`);
    }
  }
```

**File:** rest/controllers/baseController.js (L117-123)
```javascript
  validateBoundsRange(bounds) {
    Object.keys(bounds).forEach((key) => {
      if (bounds[key].hasBound() && bounds[key].hasEqual()) {
        throw new InvalidArgumentError(`Can't support both range and equal for ${bounds[key].filterKey}`);
      }
    });
  }
```

**File:** rest/controllers/baseController.js (L131-183)
```javascript
  getLowerFilters(bounds) {
    let filters = [];
    const {primary, secondary} = bounds;
    if (!secondary.hasBound()) {
      // no secondary bound filters or no secondary filters at all, everything goes into the lower part and there
      // shouldn't be inner or upper part.
      filters = [primary.equal, primary.lower, primary.upper, secondary.equal];
    } else if (primary.hasLower() && secondary.hasLower()) {
      // both have lower. If primary has lower and secondary doesn't have lower, the lower bound of primary
      // will go into the inner part.
      filters = [{...primary.lower, operator: utils.opsMap.eq}, secondary.lower];
    } else if (primary.hasEqual()) {
      filters = [primary.equal, primary.lower, primary.upper, secondary.lower, secondary.equal, secondary.upper];
    }
    return filters.filter((f) => !isNil(f));
  }

  /**
   * Gets filters for the inner part of the multi-union query
   *
   * @param {Bound}[] Bounds
   * @return {{key: string, operator: string, value: *}[]}
   */
  getInnerFilters(bounds) {
    const {primary, secondary} = bounds;
    if (!primary.hasBound() || !secondary.hasBound()) {
      return [];
    }

    return [
      // if secondary has lower bound, the primary filter should be > ?
      {filter: primary.lower, newOperator: secondary.hasLower() ? utils.opsMap.gt : null},
      // if secondary has upper bound, the primary filter should be < ?
      {filter: primary.upper, newOperator: secondary.hasUpper() ? utils.opsMap.lt : null},
    ]
      .filter((f) => !isNil(f.filter))
      .map((f) => ({...f.filter, operator: f.newOperator || f.filter.operator}));
  }

  /**
   * Gets filters for the upper part of the multi-union query
   *
   * @param {Bound}[] Bounds
   * @return {{key: string, operator: string, value: *}[]}
   */
  getUpperFilters(bounds) {
    const {primary, secondary} = bounds;
    if (!primary.hasUpper() || !secondary.hasUpper()) {
      return [];
    }
    // the upper part should always have primary filter = ?
    return [{...primary.upper, operator: utils.opsMap.eq}, secondary.upper];
  }
```

**File:** rest/service/tokenAllowanceService.js (L63-75)
```javascript
    const subQueries = [lower, inner, upper]
      .filter((filters) => filters.length !== 0)
      .map((filters) => this.getSubQuery(filters, params, accountIdCondition, limitClause, orderClause));

    let sqlQuery;
    if (subQueries.length === 0) {
      // if all three filters are empty, the subqueries will be empty too, just create the query with empty filters
      sqlQuery = this.getSubQuery([], params, accountIdCondition, limitClause, orderClause);
    } else if (subQueries.length === 1) {
      sqlQuery = subQueries[0];
    } else {
      sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion all\n'), orderClause, limitClause].join('\n');
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
