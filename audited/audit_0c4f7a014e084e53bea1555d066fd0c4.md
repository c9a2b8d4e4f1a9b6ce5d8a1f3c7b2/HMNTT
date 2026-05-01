Based on my investigation of the code, I can confirm the behavior described. Here is my analysis: [1](#0-0) 

The controller only rejects `ne` operators for `index` filters but allows all other operators (`gt`, `gte`, `lt`, `lte`, `eq`) to accumulate without any conflict detection or deduplication. [2](#0-1) 

The service blindly appends every `index` filter as an additional `AND` clause.

---

### Title
Conflicting `index` Filter Parameters Cause Empty Response in `getContractActions`

### Summary
The `getContractActions` handler in `contractController.js` accumulates all `index` query parameters into a filter list without checking for logical conflicts. These are passed to `contractService.js`'s `getContractActions`, which appends each as a separate `AND index <op> $N` SQL clause. An unprivileged user can supply mutually exclusive conditions (e.g., `index=gt:5&index=lt:3`), producing a logically unsatisfiable WHERE clause that returns zero rows where records exist.

### Finding Description
**Code path:**
- `rest/controllers/contractController.js`, `getContractActions`, lines 1229–1241: iterates `rawFilters`; for `filterKeys.INDEX`, only rejects `ne` operator (line 1235–1237), then unconditionally pushes all other index filters into `filters[]` (line 1239).
- `rest/service/contractService.js`, `getContractActions`, lines 491–498: iterates `filters`; for each entry with `key === 'index'`, appends `\nand index<op>$N` to `whereClause` with no conflict detection.

**Root cause:** The failed assumption is that a caller will only supply logically consistent index filter combinations. There is no deduplication, no operator-conflict check, and no guard against accumulating contradictory range conditions.

**Exploit flow:**
```
GET /api/v1/contracts/results/{txId}/actions?index=gt:5&index=lt:3
```
Produces SQL:
```sql
WHERE consensus_timestamp = $1 AND payer_account_id = $2
AND index > $3
AND index < $4
ORDER BY index ASC
LIMIT $5
```
With params `[..., 5, 3]`. The condition `index > 5 AND index < 3` is unsatisfiable; the query returns zero rows.

**Why existing checks fail:** The only guard (line 1235–1237) rejects `ne` operators. It does not prevent two or more range operators from being combined in a contradictory way.

### Impact Explanation
Any consumer of the `/contracts/results/{txId}/actions` endpoint — including export pipelines, monitoring tools, or downstream mirror-node integrations — receives an empty `actions` array for a transaction that has contract action records. This constitutes incorrect data delivery: records that exist in the database are silently omitted from the API response. Severity is **medium**: no data is corrupted or exfiltrated, but data availability for contract action exports is compromised on demand.

### Likelihood Explanation
Exploitation requires no authentication, no special privileges, and no knowledge beyond the public API schema. The `index` parameter is documented in the OpenAPI spec (`contractActionsIndexQueryParam`). Any external user can reproduce this trivially and repeatedly against any transaction ID. Likelihood is **high**.

### Recommendation
In the controller's filter-processing loop (`contractController.js`, lines 1234–1240), enforce that at most one lower-bound (`gt`/`gte`) and at most one upper-bound (`lt`/`lte`) index filter is accepted, and that if both are present their values are logically consistent (lower < upper). Alternatively, reject requests that supply more than two `index` parameters, or validate the combined range before forwarding to the service layer. The service layer (`contractService.js`) should not be the place for this check — validation belongs at the controller boundary.

### Proof of Concept
**Preconditions:** A transaction ID with at least one contract action record exists (e.g., `0.0.5001-1676540001-234390005`).

**Request:**
```
GET /api/v1/contracts/results/0.0.5001-1676540001-234390005/actions?index=gt:5&index=lt:3
```

**Expected (correct) behavior:** Returns contract action records with index values in the database.

**Actual behavior:** Returns `{"actions": [], "links": {"next": null}}` — zero records — because the generated SQL contains `AND index > 5 AND index < 3`, which no row can satisfy.

**Repeatability:** 100% reproducible with any valid transaction ID and any pair of contradictory index bounds.

### Citations

**File:** rest/controllers/contractController.js (L1229-1241)
```javascript
    for (const filter of rawFilters) {
      if (filter.key === filterKeys.ORDER) {
        order = filter.value;
      } else if (filter.key === filterKeys.LIMIT) {
        limit = filter.value;
      } else if (filter.key === filterKeys.INDEX) {
        if (filter.operator === utils.opsMap.ne) {
          throw InvalidArgumentError.forRequestValidation(filterKeys.INDEX);
        }

        filters.push(filter);
      }
    }
```

**File:** rest/service/contractService.js (L491-498)
```javascript
    if (filters && filters.length) {
      for (const filter of filters) {
        if (filter.key === 'index') {
          params.push(filter.value);
          whereClause += `\nand ${ContractAction.INDEX}${filter.operator}$${params.length}`;
        }
      }
    }
```
