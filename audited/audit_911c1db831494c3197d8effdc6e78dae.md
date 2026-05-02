### Title
Unauthenticated Three-Way UNION ALL Query Amplification on Token Allowances Endpoint Enables DB-Level DoS

### Summary
Any unauthenticated external user can craft a single HTTP request to `GET /api/v1/accounts/:id/allowances/tokens` with `spender.id=gte:X&spender.id=lte:Y&token.id=gte:A&token.id=lte:B` that causes `extractTokenMultiUnionQuery()` to produce a three-way `UNION ALL` query, each branch independently scanning the `token_allowance` table up to the response limit. No per-IP rate limiting exists at the application layer, so an attacker can flood the endpoint with concurrent requests, multiplying DB read load by 3× per request and potentially starving the importer's gossip-ingestion write path of DB connections and I/O bandwidth.

### Finding Description

**Route registration** — no authentication guard:
`rest/routes/accountRoute.js:18`
```js
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
```

**Controller** (`rest/controllers/tokenAllowanceController.js:68-81`) calls `extractTokenMultiUnionQuery` then immediately executes the result. No rate-limit check, no IP throttle, no auth requirement.

**Query amplification trigger** (`rest/controllers/tokenAllowanceController.js:22-59`): when both `spender.id` has a closed range (`gte` + `lte`) **and** `token.id` has a closed range (`gte` + `lte`), `getLowerFilters`, `getInnerFilters`, and `getUpperFilters` all return non-empty arrays (`rest/controllers/baseController.js:131-183`).

**Service materialises three independent sub-queries** (`rest/service/tokenAllowanceService.js:63-75`):
```js
const subQueries = [lower, inner, upper]
  .filter((filters) => filters.length !== 0)
  .map((filters) => this.getSubQuery(filters, params, accountIdCondition, limitClause, orderClause));
// ...
sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion all\n'), orderClause, limitClause].join('\n');
```

The generated SQL (confirmed by `rest/__tests__/service/tokenAllowanceService.test.js:198-234`) is:
```sql
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=$3 AND token_id>=$4 ORDER BY spender,token_id LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender>$5 AND spender<$6 ORDER BY spender,token_id LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=$7 AND token_id<=$8 ORDER BY spender,token_id LIMIT $2)
ORDER BY spender,token_id LIMIT $2
```

Three independent index range scans execute per request. The middle branch (`spender > X AND spender < Y`) has no `token_id` predicate, so it must traverse the entire spender range in the index until `LIMIT` rows are found — worst-case O(rows-in-range) index reads.

**Existing checks are insufficient:**
- `buildAndValidateFilters` caps `limit` at 100 for unauthenticated users (`rest/__tests__/utilsFilters.test.js:325-330`), but this only bounds result size, not the number of sub-queries or index pages read.
- `authHandler` (`rest/middleware/authHandler.js:15-36`) only sets a custom limit for authenticated users; unauthenticated requests pass through with no blocking.
- `maxRepeatedQueryParameters` (default 100) prevents parameter flooding but does not limit the 3-branch UNION ALL structure — that is triggered by just 4 query parameters.
- No per-IP connection or request-rate limit exists at the Node.js application layer; any infrastructure-level throttle (Traefik) is optional and not enforced by default in the REST service itself.

### Impact Explanation

Each concurrent attacker request issues three `token_allowance` table scans. Under sustained parallel requests the PostgreSQL connection pool saturates and I/O bandwidth is consumed. The Hiero importer (gossip ingestion) shares the same PostgreSQL instance and relies on timely write throughput to persist consensus transactions. DB connection exhaustion or I/O saturation directly delays or stalls gossip transaction ingestion, breaking the mirror node's core function. The attack requires zero credentials and zero knowledge of valid account IDs (any numeric ID works; the query simply returns zero rows for non-existent owners).

### Likelihood Explanation

The exploit requires only a standard HTTP client and four query parameters. It is fully repeatable, requires no authentication, no on-chain funds, and no special network position. A single attacker with a modest botnet or even a single machine with high concurrency (e.g., `ab -c 500`) can sustain the load. The endpoint is publicly documented and reachable on any mirror node deployment.

### Recommendation

1. **Add per-IP rate limiting at the application layer** (e.g., `express-rate-limit`) specifically for the `/allowances/tokens` endpoint, independent of infrastructure-level proxies.
2. **Enforce a DB statement timeout** for the REST API's PostgreSQL role (analogous to `hiero.mirror.web3.db.statementTimeout`), so runaway UNION ALL queries are killed before they exhaust resources.
3. **Restrict the three-way UNION ALL path**: if both primary and secondary bounds are open ranges, consider rewriting as a single query with composite range predicates rather than three independent sub-queries.
4. **Require authentication** (or at minimum a signed API key) for filter combinations that produce multi-branch UNION ALL queries.

### Proof of Concept

```bash
# Trigger a three-way UNION ALL with no credentials
curl -s "https://<mirror-node>/api/v1/accounts/0.0.1/allowances/tokens?\
spender.id=gte:0.0.1&spender.id=lte:0.0.9999999&\
token.id=gte:0.0.1&token.id=lte:0.0.9999999&limit=100"

# Flood with concurrent requests (no auth required)
ab -n 100000 -c 500 \
  "https://<mirror-node>/api/v1/accounts/0.0.1/allowances/tokens?\
spender.id=gte:0.0.1&spender.id=lte:0.0.9999999&\
token.id=gte:0.0.1&token.id=lte:0.0.9999999&limit=100"
```

Each request generates the three-branch `UNION ALL` SQL shown above. At 500 concurrent connections this issues 1 500 simultaneous `token_allowance` index scans, exhausting the DB connection pool and degrading gossip-ingestion write latency. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rest/routes/accountRoute.js (L18-18)
```javascript
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
```

**File:** rest/controllers/tokenAllowanceController.js (L22-59)
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

**File:** rest/controllers/baseController.js (L154-168)
```javascript
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

**File:** rest/__tests__/service/tokenAllowanceService.test.js (L198-234)
```javascript
      name: 'spender closed range and token closed range',
      query: {
        ...defaultQuery,
        lower: [
          {key: SPENDER_ID, operator: eq, value: 2},
          {key: TOKEN_ID, operator: gte, value: 100},
        ],
        inner: [
          {key: SPENDER_ID, operator: gt, value: 2},
          {key: SPENDER_ID, operator: lt, value: 8},
        ],
        upper: [
          {key: SPENDER_ID, operator: eq, value: 8},
          {key: TOKEN_ID, operator: lte, value: 200},
        ],
      },
      expected: {
        sqlQuery: `(select * from token_allowance
            where owner = $1 and amount > 0 and spender = $3 and token_id >= $4
            order by spender asc, token_id asc
            limit $2
          ) union all (
            select * from token_allowance
            where owner = $1 and amount > 0 and spender > $5 and spender < $6
            order by spender asc, token_id asc
            limit $2
          ) union all (
            select * from token_allowance
            where owner = $1 and amount > 0 and spender = $7 and token_id <= $8
            order by spender asc, token_id asc
            limit $2
          )
          order by spender asc, token_id asc
          limit $2`,
        params: [1, 25, 2, 100, 2, 8, 8, 200],
      },
    },
```
