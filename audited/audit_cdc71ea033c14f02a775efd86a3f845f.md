### Title
3x Database Row Read Amplification via UNION ALL Subquery Limit Multiplication in `getQuery()`

### Summary
In `rest/service/tokenAllowanceService.js`, `getQuery()` constructs up to three independent subqueries each carrying the same `LIMIT $2` clause. When all three subqueries are active (lower + inner + upper), the database independently scans up to `limit` rows per subquery before the outer `LIMIT` is applied, multiplying actual row reads by up to 3×. Any unauthenticated user can trigger this branch and set `limit` to the system maximum (100 by default), causing the database to read up to 300 rows for a query that returns at most 100.

### Finding Description

**Code path:**

`rest/controllers/tokenAllowanceController.js` `extractTokenMultiUnionQuery()` (line 38–39) reads the already-validated `filter.value` for `LIMIT` directly into `limit`: [1](#0-0) 

`rest/utils.js` `formatComparator()` (line 1395–1397) does cap the limit at `getEffectiveMaxLimit()` (100 for unauthenticated users): [2](#0-1) 

However, in `rest/service/tokenAllowanceService.js` `getQuery()` (lines 56–74), the same `limitClause = super.getLimitQuery(2)` (i.e., `LIMIT $2`) is injected into **every** subquery: [3](#0-2) 

When `lower`, `inner`, and `upper` are all non-empty, the generated SQL is:

```sql
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=$3 AND token_id>=$4
 ORDER BY spender ASC, token_id ASC LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender>$5 AND spender<$6
 ORDER BY spender ASC, token_id ASC LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=$7 AND token_id<=$8
 ORDER BY spender ASC, token_id ASC LIMIT $2)
ORDER BY spender ASC, token_id ASC
LIMIT $2
```

Each subquery independently fetches up to `$2` rows from `token_allowance` before the outer `LIMIT $2` is applied. The database performs up to `3 × limit` row reads to satisfy a query that returns at most `limit` rows.

**Root cause:** The `limitClause` is shared across all subqueries without reduction. The outer `LIMIT` is applied only after all three subqueries have already been fully evaluated.

**Why the existing cap is insufficient:** `formatComparator` correctly caps `limit` at `responseLimit.max` (100). This prevents a single subquery from reading more than 100 rows. But it does not prevent the 3× amplification: with `limit=100`, the DB reads up to 300 rows total. The cap addresses the per-subquery bound, not the aggregate bound across the UNION ALL.

### Impact Explanation

With the default `responseLimit.max = 100`, a single crafted request causes the database to read up to 300 rows from `token_allowance` while returning at most 100. This is a 3× amplification of database I/O per request compared to a simple query. Under concurrent load from multiple such requests, this amplification compounds and can drive database CPU and I/O consumption significantly above baseline. The `token_allowance` table is scanned three times per request for the same owner, with overlapping index ranges, increasing buffer pool pressure and query execution time.

### Likelihood Explanation

No authentication is required. The 3-subquery branch is triggered by a standard, documented query pattern: providing both a lower and upper bound on `spender.id` combined with a bound on `token.id` (e.g., `spender.id=gte:1&spender.id=lte:9999999&token.id=gte:1&token.id=lte:9999999&limit=100`). This is a normal pagination use case. Any external user who reads the API documentation can craft this request. The attack is repeatable, stateless, and requires no prior knowledge of the data.

### Recommendation

Apply a per-subquery limit reduction when multiple subqueries are combined. Specifically, when `subQueries.length > 1`, pass a reduced limit (e.g., `Math.ceil(limit / subQueries.length)` or simply `limit`) only to the outer query, and use an unbounded or internally-capped subquery scan. Alternatively, restructure the UNION ALL to not apply `LIMIT` inside each branch, relying solely on the outer `LIMIT` clause. A simpler mitigation is to lower `responseLimit.max` for this endpoint specifically, or to document and rate-limit the multi-bound query pattern.

### Proof of Concept

**Precondition:** A `token_allowance` table populated with rows for a given owner across multiple spenders and token IDs.

**Request (no authentication required):**
```
GET /api/v1/accounts/0.0.1234/allowances/tokens?spender.id=gte:0.0.1&spender.id=lte:0.0.9999999&token.id=gte:0.0.1&token.id=lte:0.0.9999999&limit=100
```

**Trigger:** `spender.id=gte:1` and `spender.id=lte:9999999` with `token.id` bounds causes `extractTokenMultiUnionQuery` to populate all three of `lower`, `inner`, and `upper`, triggering the 3-subquery UNION ALL branch in `getQuery()`.

**Result:** The database executes three independent `SELECT * FROM token_allowance ... LIMIT 100` scans before applying the outer `LIMIT 100`, reading up to 300 rows to return 100. Repeating this request in a loop (without brute-force volume) amplifies database load by 3× per request compared to a simple `limit=100` query.

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L38-39)
```javascript
        case filterKeys.LIMIT:
          limit = filter.value;
```

**File:** rest/utils.js (L1395-1397)
```javascript
      case constants.filterKeys.LIMIT:
        comparator.value = Math.min(Number(comparator.value), getEffectiveMaxLimit());
        break;
```

**File:** rest/service/tokenAllowanceService.js (L56-75)
```javascript
    const params = [ownerAccountId, limit];
    const accountIdCondition = `${TokenAllowance.OWNER} = $1`;
    const limitClause = super.getLimitQuery(2);
    const orderClause = super.getOrderByQuery(
      ...TokenAllowanceService.orderByColumns.map((column) => OrderSpec.from(column, order))
    );

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
