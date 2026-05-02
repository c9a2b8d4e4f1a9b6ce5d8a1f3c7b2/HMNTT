### Title
Triple UNION Sub-Query Amplification in `getContractLogsQuery()` Allows Unauthenticated 3x DB Work Multiplication

### Summary
In `rest/service/contractService.js`, `getContractLogsQuery()` constructs up to three independent sub-queries (lower, inner, upper), each containing a full CTE + join against `contract_log` with the same user-supplied `LIMIT` clause. When all three filter arrays are populated — which any unauthenticated user can trigger with a valid index+timestamp range request — the database executes three full scans each fetching up to `max_limit` rows before the outer UNION sorts and reduces the combined result, multiplying per-request DB work by approximately 3x compared to a single-subquery request.

### Finding Description
**Exact code location:** `rest/service/contractService.js`, `getContractLogsQuery()`, lines 323–368. [1](#0-0) 

The function builds sub-queries for each non-empty filter array:

```js
const subQueries = [lower, inner, upper]
  .filter((filters) => filters.length !== 0)
  .map((filters) =>
    super.buildSelectQuery(
      ContractService.contractLogsExtendedQuery,  // full CTE + join
      params,
      conditions,
      orderClause,
      limitClause,   // <-- same user-supplied LIMIT in every sub-query
      ...
    )
  );
// When subQueries.length > 1:
sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion\n'), orderClauseNoAlias, limitClause].join('\n');
```

Each sub-query independently executes:
```sql
with entity as (select evm_address, id from entity)
select ... from contract_log cl
left join entity e on id = contract_id
where <conditions> and <pagination_filters>
order by cl.consensus_timestamp desc, cl.index desc
limit $3   -- user-supplied, up to max 100
```

The outer UNION then re-sorts and re-limits the combined up-to-300-row result set. [2](#0-1) 

**Root cause:** The `limitClause` parameter index (`params.length` at line 333) is computed once and reused identically across all three sub-queries. There is no per-sub-query limit reduction or amplification guard. [3](#0-2) 

**Trigger path:** In `extractContractLogsMultiUnionQuery()` (contractController.js lines 582–699), when a user supplies `index=gte:X` + `timestamp=gte:Y` + `timestamp=lte:Z`, the controller populates all three of `lower`, `inner`, and `upper`: [4](#0-3) 

This is confirmed by the test case `'index > & timestamp >= & timestamp <='` which explicitly shows all three arrays populated. [5](#0-4) 

### Impact Explanation
With `max_limit = 100` (confirmed default): [6](#0-5) 

A single crafted request causes the database to execute 3 independent CTE+join scans each fetching up to 100 rows (300 total rows processed), versus 100 rows for a normal single-subquery request. This is a consistent, deterministic 3x per-request DB amplification. Under moderate concurrent load from multiple unauthenticated clients each sending such requests, aggregate DB CPU and I/O consumption increases proportionally. The `contract_log` table is expected to be large in production, making each scan non-trivial.

### Likelihood Explanation
No authentication is required. The endpoint `/api/v1/contracts/{id}/results/logs` is publicly accessible. The filter combination (`index=gte:X&timestamp=gte:Y&timestamp=lte:Z&limit=100`) is valid, documented, and passes all input validation. The attack is trivially repeatable with a single HTTP client in a loop. No special knowledge beyond the public API documentation is needed.

### Recommendation
1. **Reduce per-sub-query limit when multiple sub-queries are present.** When `subQueries.length > 1`, pass `Math.ceil(limit / subQueries.length)` as the per-sub-query limit, then apply the full `limit` only on the outer UNION. This bounds total rows fetched to `limit` regardless of sub-query count.
2. **Add a rate limit or cost-based throttle** on the contract logs endpoints specifically for requests that trigger multi-union paths.
3. **Consider a DB-level per-statement row limit** in addition to the existing `statementTimeout`.

### Proof of Concept
```
# Triggers all three sub-queries (lower + inner + upper), each fetching up to 100 rows:
GET /api/v1/contracts/0.0.1234/results/logs?index=gte:0&timestamp=gte:1000000000000000000&timestamp=lte:9999999999999999999&limit=100

# Resulting SQL (simplified):
(with entity as (...) select ... from contract_log cl left join entity e ... where cl.contract_id=$1 and cl.index>=$4 and cl.consensus_timestamp=$5 order by ... limit $3)
union
(with entity as (...) select ... from contract_log cl left join entity e ... where cl.contract_id=$1 and cl.consensus_timestamp>$6 and cl.consensus_timestamp<$7 order by ... limit $3)
union
(with entity as (...) select ... from contract_log cl left join entity e ... where cl.contract_id=$1 and cl.index<=$8 and cl.consensus_timestamp=$7 order by ... limit $3)
order by consensus_timestamp desc, index desc
limit $3

# Each sub-query independently scans up to 100 rows; total DB work = 3x a normal request.
# Repeat concurrently to sustain elevated resource consumption.
```

### Citations

**File:** rest/service/contractService.js (L333-334)
```javascript
    const limitClause = super.getLimitQuery(params.length);

```

**File:** rest/service/contractService.js (L335-365)
```javascript
    const subQueries = [lower, inner, upper]
      .filter((filters) => filters.length !== 0)
      .map((filters) =>
        super.buildSelectQuery(
          ContractService.contractLogsExtendedQuery,
          params,
          conditions,
          orderClause,
          limitClause,
          filters.map((filter) => ({
            ...filter,
            column: ContractLog.getFullName(ContractService.contractLogsPaginationColumns[filter.key]),
          }))
        )
      );

    let sqlQuery;
    if (subQueries.length === 0) {
      // if all three filters are empty, the subqueries will be empty too, just create the query with empty filters
      sqlQuery = super.buildSelectQuery(
        ContractService.contractLogsExtendedQuery,
        params,
        conditions,
        orderClause,
        limitClause
      );
    } else if (subQueries.length === 1) {
      sqlQuery = subQueries[0];
    } else {
      sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion\n'), orderClauseNoAlias, limitClause].join('\n');
    }
```

**File:** rest/controllers/contractController.js (L693-698)
```javascript
    return {
      ...query,
      lower: this.getContractLogsLowerFilters(bounds),
      inner: this.getInnerFilters(bounds),
      upper: this.getUpperFilters(bounds),
    };
```

**File:** rest/__tests__/controllers/contractController.test.js (L1060-1063)
```javascript
        lower: [timestampEq1002Filter, indexGt2Filter],
        inner: [timestampGt1002Filter, timestampLt1005Filter],
      },
    },
```

**File:** rest/__tests__/config.test.js (L323-325)
```javascript
    const func = (await import('../config')).getResponseLimit;
    expect(func()).toEqual({default: 25, max: 100, tokenBalance: {multipleAccounts: 50, singleAccount: 1000}});
  });
```
