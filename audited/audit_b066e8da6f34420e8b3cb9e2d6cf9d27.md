### Title
Unrestricted Combination of `spender.id` IN-List and Range Filter Causes Amplified DB Work in `getAccountCryptoAllowances`

### Summary
`CryptoAllowanceController.extractCryptoAllowancesQuery()` accepts up to 100 `spender.id` equality values (collapsed into a SQL `IN` clause) simultaneously with one or more `spender.id` range conditions (`gt`/`gte`/`lt`/`lte`) on the same column, with no guard preventing their combination. Unlike `TokenAllowanceController`, which uses `Bound.validateBoundsRange()` to reject mixed equal+range filters, `CryptoAllowanceController` has no equivalent check. Any unauthenticated caller can craft a single request that forces the database to evaluate a 100-element `IN` predicate together with a range predicate, a reverse-ordered scan, and a `LIMIT 1`, wasting disproportionate DB resources per request.

### Finding Description

**Code path:**

`rest/controllers/cryptoAllowanceController.js`, `extractCryptoAllowancesQuery()`, lines 26–68:

```
for (const filter of filters) {
  case filterKeys.SPENDER_ID:
    // ne blocked, but eq+range combination is NOT blocked
    this.updateConditionsAndParamsWithInValues(
      filter, spenderInValues, params, conditions,
      CryptoAllowance.SPENDER, conditions.length + 1
    );
``` [1](#0-0) 

`updateConditionsAndParamsWithInValues` in `BaseController` routes `eq` filters into `spenderInValues` and range filters directly into `conditions`. Both paths are independent and additive: [2](#0-1) 

After the loop, `updateQueryFiltersWithInValues` appends the `IN (...)` clause unconditionally alongside any already-present range conditions: [3](#0-2) 

The resulting SQL sent to `CryptoAllowanceService.getAccountAllowancesQuery` is:

```sql
SELECT * FROM crypto_allowance
WHERE owner = $1
  AND spender > $2          -- range condition
  AND spender IN ($3,...,$102)  -- 100-element IN list
  AND amount > 0
ORDER BY spender DESC
LIMIT 1
``` [4](#0-3) 

**Root cause / failed assumption:** The code assumes callers will not mix equality and range filters for `spender.id`. `TokenAllowanceController` explicitly prevents this via `validateBoundsRange()` (which throws `InvalidArgumentError` when both `hasBound()` and `hasEqual()` are true for the same field), but `CryptoAllowanceController` never calls any equivalent check. [5](#0-4) 

**Existing checks reviewed:**

- `ne` operator is blocked (line 36–38 of the controller) — does not prevent the eq+range combination.
- `maxRepeatedQueryParameters` defaults to **100**, enforced by `buildFilters` and the `qs` parser's `arrayLimit`: [6](#0-5) [7](#0-6) 

This means an attacker is permitted to supply exactly 100 `spender.id` equality values — the maximum the system allows — combined with a range filter. No check rejects this combination.

### Impact Explanation

Each such request forces the database to:
1. Evaluate a 100-element `IN` predicate on every candidate row.
2. Simultaneously apply a range predicate on the same indexed column.
3. Perform a full reverse-ordered index scan (due to `ORDER BY spender DESC`).
4. Return only 1 row (`LIMIT 1`), discarding all other work.

The DB connection pool is capped at 10 connections with a 20-second statement timeout: [8](#0-7) 

A sustained stream of such requests (10 concurrent, each holding a connection for up to 20 seconds) can saturate the pool and delay or time out legitimate queries, degrading service for all users. There is no visible rate limiting on this endpoint.

### Likelihood Explanation

Preconditions: none. Any external user with network access can call `/api/v1/accounts/{id}/allowances/crypto`. The exploit requires only crafting a URL with 100 `spender.id` query parameters plus one range parameter — trivially scriptable with `curl` or any HTTP client. It is repeatable at will, requires no credentials, and produces no on-chain cost.

### Recommendation

Apply the same `Bound`-based validation used in `TokenAllowanceController`: reject requests that supply both equality (`eq`) and range (`gt`/`gte`/`lt`/`lte`) values for `spender.id` simultaneously. Concretely, refactor `extractCryptoAllowancesQuery` to use a `Bound` object for `spender.id` and call `this.validateBoundsRange(bounds)` before building the query. Additionally, consider adding per-IP or per-endpoint rate limiting for allowance list endpoints.

### Proof of Concept

```bash
# Build a URL with 100 spender.id equality values + 1 range filter + order=desc + limit=1
BASE="http://<mirror-node>/api/v1/accounts/0.0.1234/allowances/crypto"
PARAMS="order=desc&limit=1&spender.id=gt:0.0.1"
for i in $(seq 2 101); do
  PARAMS="${PARAMS}&spender.id=0.0.${i}"
done

# Fire repeatedly to saturate the DB pool
for j in $(seq 1 50); do
  curl -s "${BASE}?${PARAMS}" &
done
wait
```

Each request generates a query with `spender > $2 AND spender IN ($3…$102) AND amount > 0 ORDER BY spender DESC LIMIT 1`, forcing the DB to evaluate 100 IN-list members against a reverse-ordered scan while returning only one row. Sustained parallel requests exhaust the 10-connection pool and degrade response times for all other API consumers.

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L33-57)
```javascript
    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.SPENDER_ID:
          if (utils.opsMap.ne === filter.operator) {
            throw new InvalidArgumentError(`Not equal (ne) comparison operator is not supported for ${filter.key}`);
          }
          this.updateConditionsAndParamsWithInValues(
            filter,
            spenderInValues,
            params,
            conditions,
            CryptoAllowance.SPENDER,
            conditions.length + 1
          );
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
```

**File:** rest/controllers/baseController.js (L12-27)
```javascript
  updateConditionsAndParamsWithInValues = (
    filter,
    invalues,
    existingParams,
    existingConditions,
    fullName,
    position = existingParams.length
  ) => {
    if (filter.operator === utils.opsMap.eq) {
      // aggregate '=' conditions and use the sql 'in' operator
      invalues.push(filter.value);
    } else {
      existingParams.push(filter.value);
      existingConditions.push(`${fullName}${filter.operator}$${position}`);
    }
  };
```

**File:** rest/controllers/baseController.js (L29-44)
```javascript
  updateQueryFiltersWithInValues = (
    existingParams,
    existingConditions,
    invalues,
    fullName,
    start = existingParams.length + 1
  ) => {
    if (!isNil(invalues) && !isEmpty(invalues)) {
      // add the condition 'c.id in ()'
      existingParams.push(...invalues);
      const positions = range(invalues.length)
        .map((position) => position + start)
        .map((position) => `$${position}`);
      existingConditions.push(`${fullName} in (${positions})`);
    }
  };
```

**File:** rest/service/cryptoAllowanceService.js (L19-30)
```javascript
  getAccountAllowancesQuery(whereConditions, whereParams, order, limit) {
    const params = whereParams;
    params.push(limit);
    const query = [
      CryptoAllowanceService.accountAllowanceQuery,
      whereConditions.length > 0 ? `where ${whereConditions.join(' and ')}` : '',
      super.getOrderByQuery(OrderSpec.from(CryptoAllowance.SPENDER, order)),
      super.getLimitQuery(params.length),
    ].join('\n');

    return {query, params};
  }
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

**File:** rest/utils.js (L1241-1248)
```javascript
      if (!isRepeatedQueryParameterValidLength(values)) {
        badParams.push({
          code: InvalidArgumentError.PARAM_COUNT_EXCEEDS_MAX_CODE,
          key,
          count: values.length,
          max: config.query.maxRepeatedQueryParameters,
        });
        continue;
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

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
