Based on my investigation of the full code path, I have enough to render a verdict.

**Key findings:**

1. `getTokenRelationships()` calls `buildAndValidateFilters(req.query, acceptedTokenParameters)` with no custom dependency checker override — it uses the default `filterDependencyCheck`. [1](#0-0) 

2. `extractTokensRelationshipQuery()` blindly appends every `token.id` range filter into `conditions[]` with no cross-filter range validation. [2](#0-1) 

3. `TokenService.getTokenRelationshipsQuery()` joins all conditions with `AND`, producing SQL like `WHERE ta.account_id = $1 AND ta.associated = true AND ta.token_id > $3 AND ta.token_id < $4` — with no guard against impossible ranges. [3](#0-2) 

4. `isEmptyRange()` exists in `utils.js` and correctly detects contradictory ranges, but it is **only called from `getNextParamQueries()`** (pagination link generation) — never from the filter validation pipeline for this endpoint. [4](#0-3) 

5. Timestamp filters have explicit contradictory-range rejection (`parseTimestampFilters`), but no equivalent exists for `token.id`. [5](#0-4) 

6. The `Bound` class enforces single gt/gte and single lt/lte per key, but it is **not used** in `tokenController.js` — only in other controllers. [6](#0-5) 

---

### Title
Unvalidated Contradictory `token.id` Range Filters Cause Wasteful DB Queries in `getTokenRelationships`

### Summary
The `getTokenRelationships` endpoint in `rest/controllers/tokenController.js` accepts multiple `token.id` range filters (e.g., `token.id=gt:1000&token.id=lt:500`) without validating that the combined range is non-empty. Both filters pass individual validation and are forwarded directly to the database as contradictory `AND` conditions, causing the DB to execute a query that is guaranteed to return zero rows on every such request. Any unauthenticated user can exploit this to generate sustained, wasteful DB load.

### Finding Description
**Code path:**
- `GET /api/v1/accounts/0.0.1001/tokens?token.id=gt:1000&token.id=lt:500`
- `getTokenRelationships()` → `buildAndValidateFilters()` validates each filter individually (both are valid entity IDs) → `extractTokensRelationshipQuery()` pushes both into `conditions[]` without cross-filter range checking → `TokenService.getTokenRelationshipsQuery()` builds: `WHERE ta.account_id = $1 AND ta.associated = true AND ta.token_id > $3 AND ta.token_id < $4` (params: `[accountId, limit, 1000, 500]`) → DB executes, finds no rows, returns empty result.

**Root cause:** `extractTokensRelationshipQuery()` accumulates all `token.id` range filters into a flat `conditions` array with no cross-condition range sanity check. [7](#0-6) 

**Why existing checks fail:**
- `buildAndValidateFilters` validates each filter value in isolation (is it a valid entity ID? yes). [8](#0-7) 
- `isEmptyRange()` is never invoked in the request-handling path for this endpoint. [9](#0-8) 
- The `Bound` class range enforcement is not wired into `tokenController.js`. [10](#0-9) 
- No rate-limiting or request-cost throttling is visible at the controller layer.

### Impact Explanation
Each request causes a full DB query execution against the `token_account` table (indexed on `account_id`, `token_id`). While PostgreSQL will short-circuit the impossible range quickly, the connection overhead, query planning, and index traversal still consume DB resources. Under sustained automated request load (e.g., thousands of requests/second from a botnet or single high-throughput client), this can degrade DB connection pool availability and increase latency for legitimate users. No economic damage occurs to any on-chain user; the impact is purely operational (griefing/DoS of the mirror node service). Severity: **Low-Medium** (griefing, no funds at risk).

### Likelihood Explanation
Preconditions are minimal: the attacker needs only a valid account ID (publicly enumerable from the same API) and the ability to send HTTP requests. No authentication, no tokens, no privileged access required. The attack is trivially scriptable and repeatable indefinitely. Any external actor aware of the API can execute it.

### Recommendation
1. **Reject contradictory ranges at validation time:** In `extractTokensRelationshipQuery()` (or in `buildAndValidateFilters` via a custom `filterDependencyChecker`), call `isEmptyRange(filterKeys.TOKEN_ID, req.query['token.id'])` and throw `InvalidArgumentError` if it returns `true`.
2. **Alternatively, use the `Bound` class** (already used in other controllers) to enforce single gt/gte and single lt/lte for `token.id`, and add a cross-bound range check.
3. **Apply rate limiting** at the API gateway or middleware layer for all `/accounts/:id/tokens` requests.

### Proof of Concept
```
# Step 1: Find any valid account ID (publicly available)
GET /api/v1/accounts?limit=1
# -> returns e.g. account 0.0.1001

# Step 2: Send contradictory range request (no auth required)
GET /api/v1/accounts/0.0.1001/tokens?token.id=gt:9999999&token.id=lt:1
# -> HTTP 200, {"tokens": [], "links": {"next": null}}
# DB executes: WHERE ta.account_id = 1001 AND ta.associated = true
#              AND ta.token_id > 9999999 AND ta.token_id < 1
# -> impossible range, zero rows, wasted query

# Step 3: Repeat in a tight loop
for i in $(seq 1 10000); do
  curl -s "http://mirror-node/api/v1/accounts/0.0.1001/tokens?token.id=gt:9999999&token.id=lt:1" &
done
# -> sustained DB resource consumption with no legitimate results
```

### Citations

**File:** rest/controllers/tokenController.js (L22-58)
```javascript
  extractTokensRelationshipQuery = (filters, ownerAccountId) => {
    const conditions = [];
    const inConditions = [];
    let limit = defaultLimit;
    let order = orderFilterValues.ASC;

    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.TOKEN_ID:
          if (utils.opsMap.ne === filter.operator) {
            throw new InvalidArgumentError(`Not equal (ne) comparison operator is not supported for ${filter.key}`);
          }
          if (utils.opsMap.eq === filter.operator) {
            inConditions.push({key: TokenAccount.TOKEN_ID, operator: filter.operator, value: filter.value});
          } else {
            conditions.push({key: TokenAccount.TOKEN_ID, operator: filter.operator, value: filter.value});
          }
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

    return {
      conditions,
      inConditions,
      order,
      ownerAccountId,
      limit,
    };
  };
```

**File:** rest/controllers/tokenController.js (L72-73)
```javascript
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenParameters);
    const query = this.extractTokensRelationshipQuery(filters, accountId);
```

**File:** rest/service/tokenService.js (L50-58)
```javascript
    const moreConditionsExist = conditions.length > 0 ? ` and ` : ``;
    const conditionClause =
      moreConditionsExist +
      conditions
        .map((condition) => {
          params.push(condition.value);
          return `${TokenAccount.getFullName(condition.key)} ${condition.operator} $${params.length}`;
        })
        .join(' and ');
```

**File:** rest/utils.js (L888-890)
```javascript
  if (isEmptyRange(primaryField, reqQuery[primaryField])) {
    return null;
  }
```

**File:** rest/utils.js (L901-946)
```javascript
const isEmptyRange = (key, value) => {
  const values = Array.isArray(value) ? value : [value];
  let lower = null;
  let upper = null;

  for (const v of values) {
    if (!gtLtPattern.test(v)) {
      continue;
    }

    const filter = buildComparatorFilter(key, v);
    formatComparator(filter);

    // formatComparator doesn't handle CONTRACT_ID and SLOT
    if (key === constants.filterKeys.CONTRACT_ID) {
      filter.value = EntityId.parse(filter.value).getEncodedId();
    } else if (key === constants.filterKeys.SLOT) {
      filter.value = addHexPrefix(filter.value);
    }

    if (filter.value == null) {
      continue;
    }

    let parsed = BigInt(filter.value);
    switch (filter.operator) {
      case opsMap.gt:
        parsed += 1n;
      case opsMap.gte:
        lower = lower === null ? parsed : bigIntMax(lower, parsed);
        break;
      case opsMap.lt:
        parsed -= 1n;
      case opsMap.lte:
        upper = upper === null ? parsed : bigIntMin(upper, parsed);
        break;
      default:
        break;
    }
  }

  if (lower === null || upper === null) {
    return false;
  }

  return upper < lower;
```

**File:** rest/utils.js (L1208-1226)
```javascript
const buildAndValidateFilters = (
  query,
  acceptedParameters,
  filterValidator = filterValidityChecks,
  filterDependencyChecker = filterDependencyCheck
) => {
  const {badParams, filters} = buildFilters(query);
  const {invalidParams, unknownParams} = validateAndParseFilters(filters, filterValidator, acceptedParameters);
  badParams.push(...invalidParams);
  badParams.push(...unknownParams);
  if (badParams.length > 0) {
    throw InvalidArgumentError.forRequestValidation(badParams);
  }

  if (filterDependencyChecker) {
    filterDependencyChecker(query);
  }

  return filters;
```

**File:** rest/utils.js (L1657-1665)
```javascript
  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
    }
```

**File:** rest/controllers/bound.js (L14-68)
```javascript
class Bound {
  constructor(filterKey, viewModelKey) {
    this.filterKey = filterKey;
    this.viewModelKey = !isNil(viewModelKey) ? viewModelKey : filterKey;
    this.equal = null;
    this.lower = null;
    this.next = null;
    this.upper = null;
  }

  getAllFilters() {
    return [this.equal, this.lower, this.upper].filter((filter) => filter !== null);
  }

  hasBound() {
    return this.hasLower() || this.hasUpper();
  }

  hasEqual() {
    return !isNil(this.equal);
  }

  hasLower() {
    return !isNil(this.lower);
  }

  hasUpper() {
    return !isNil(this.upper);
  }

  isEmpty() {
    return !this.hasEqual() && !this.hasLower() && !this.hasUpper();
  }

  parse(filter) {
    const operator = filter.operator;
    if (operator === utils.opsMap.eq) {
      if (this.hasEqual()) {
        throw new InvalidArgumentError(`Only one equal (eq) operator is allowed for ${this.filterKey}`);
      }
      this.equal = filter;
    } else if (utils.gtGte.includes(operator)) {
      if (this.hasLower()) {
        throw new InvalidArgumentError(`Only one gt/gte operator is allowed for ${this.filterKey}`);
      }
      this.lower = filter;
    } else if (utils.ltLte.includes(operator)) {
      if (this.hasUpper()) {
        throw new InvalidArgumentError(`Only one lt/lte operator is allowed for ${this.filterKey}`);
      }
      this.upper = filter;
    } else {
      throw new InvalidArgumentError(`Not equal (ne) operator is not supported for ${this.filterKey}`);
    }
  }
```
