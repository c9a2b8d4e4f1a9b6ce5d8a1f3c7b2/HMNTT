### Title
Unbounded `spender.id=eq:X` Parameter Accumulation Leads to Arbitrarily Large SQL IN Clause in `/accounts/:id/nfts`

### Summary
An unauthenticated attacker can send a single HTTP request to `GET /accounts/:idOrAliasOrEvmAddress/nfts` with an arbitrary number of `spender.id=eq:X` query parameters. Each `eq` filter is unconditionally appended to the `spenderIdInFilters` array with no upper bound, and the entire array is then materialized verbatim into a SQL `IN (...)` clause executed against the `nft` table. No existing validation rejects or caps the count of `eq`-operator spender filters.

### Finding Description

**Accumulation — `accountController.js` `extractNftMultiUnionQuery()`, line 59:**

```js
case filterKeys.SPENDER_ID:
  filter.operator === utils.opsMap.eq
    ? spenderIdInFilters.push(filter)   // ← unbounded push, no cap
    : spenderIdFilters.push(filter);
  break;
``` [1](#0-0) 

`validateFilters()` is called immediately after but only rejects multiple range operators (`lt/lte/gt/gte`) and the `ne` operator; it contains zero logic to limit the count of `eq` entries: [2](#0-1) 

**IN-clause construction — `nftService.js` `getSubQuery()`, lines 66-73:**

```js
if (!isEmpty(spenderIdInFilters)) {
  const paramsForCondition = spenderIdInFilters.map((filter) => {
    params.push(filter.value);
    return `$${params.length}`;
  });
  conditions.push(`${Nft.SPENDER} in (${paramsForCondition})`);
}
``` [3](#0-2) 

Every value supplied by the attacker is pushed into `params` and emitted as a positional placeholder. With N attacker-supplied values the generated SQL becomes:

```sql
... WHERE account_id = $1 AND spender IN ($3, $4, ..., $N+2)
```

with no server-side cap on N.

**Root cause:** The `acceptedNftAccountParameters` set permits `filterKeys.SPENDER_ID` as a key but imposes no cardinality limit on how many times that key may appear. HTTP allows repeated query parameters, so `?spender.id=eq:1&spender.id=eq:2&...` is legal input that the framework will parse into an array of filter objects, all of which flow through to the SQL layer. [4](#0-3) 

### Impact Explanation

A single unauthenticated request carrying thousands of `spender.id=eq:X` values forces the database to evaluate a massive `IN` list against the `nft` table. PostgreSQL's query planner may fall back to a sequential scan when the IN list is large enough to make index lookups less attractive. Even when an index is used, each request consumes a database connection for the full duration of the query and allocates proportional memory for the parameter list. Repeated concurrent requests of this kind exhaust the connection pool and starve legitimate transaction-confirmation queries of database access, constituting a denial-of-service against the mirror node's read path and, indirectly, against any downstream service that depends on it.

### Likelihood Explanation

The endpoint is publicly accessible with no authentication requirement. The attack requires only a standard HTTP client and knowledge of the public API schema (documented in `openapi.yml`). It is trivially repeatable and scriptable. No special account, token, or on-chain state is needed; the attacker does not even need a valid account ID because the account lookup happens before the NFT query but the expensive query is still constructed and executed regardless of whether the account exists.

### Recommendation

1. **Cap the number of `eq` filters per parameter key** inside `buildAndValidateFilters` or at the entry of `extractNftMultiUnionQuery`. A reasonable limit (e.g., 20–50 values) should be enforced and an `InvalidArgumentError` thrown when exceeded.
2. **Enforce a maximum query-parameter count** globally in the Express middleware layer so that no single request can supply more than a configured ceiling of repeated parameters.
3. **Set a statement timeout** on the database connection used by the mirror-node REST service so that runaway queries are killed before they exhaust pool resources.

### Proof of Concept

```bash
# Build a URL with 500 spender.id=eq:X parameters
PARAMS=$(python3 -c "print('&'.join(f'spender.id=eq:{i}' for i in range(1,501)))")

curl -s "http://<mirror-node-host>/api/v1/accounts/0.0.1000/nfts?$PARAMS"
```

**Preconditions:** None — no authentication, no on-chain state required.

**Trigger:** The request is parsed; `extractNftMultiUnionQuery` accumulates 500 entries in `spenderIdInFilters`; `NftService.getSubQuery` emits `spender IN ($3,$4,...,$502)`; the database executes the query holding a connection for its duration.

**Result:** Repeated concurrent requests of this form exhaust the database connection pool, causing subsequent legitimate queries (including transaction-confirmation reads) to queue or fail with connection-pool-exhausted errors.

### Citations

**File:** rest/controllers/accountController.js (L18-32)
```javascript
  validateFilters(bounds, spenderIdFilters) {
    this.validateBounds(bounds);

    const spenderOperators = spenderIdFilters.map((f) => f.operator);
    if (
      spenderOperators.filter((o) => o === utils.opsMap.lte || o === utils.opsMap.lt).length > 1 ||
      spenderOperators.filter((o) => o === utils.opsMap.gte || o === utils.opsMap.gt).length > 1
    ) {
      throw new InvalidArgumentError(`Multiple range params not allowed for spender.id`);
    }

    if (spenderIdFilters.some((f) => f.operator === utils.opsMap.ne)) {
      throw new InvalidArgumentError(`Not equals (ne) comparison operator is not supported`);
    }
  }
```

**File:** rest/controllers/accountController.js (L58-60)
```javascript
        case filterKeys.SPENDER_ID:
          filter.operator === utils.opsMap.eq ? spenderIdInFilters.push(filter) : spenderIdFilters.push(filter);
          break;
```

**File:** rest/controllers/accountController.js (L206-212)
```javascript
const acceptedNftAccountParameters = new Set([
  filterKeys.LIMIT,
  filterKeys.ORDER,
  filterKeys.SERIAL_NUMBER,
  filterKeys.SPENDER_ID,
  filterKeys.TOKEN_ID,
]);
```

**File:** rest/service/nftService.js (L66-73)
```javascript
    if (!isEmpty(spenderIdInFilters)) {
      const paramsForCondition = spenderIdInFilters.map((filter) => {
        params.push(filter.value);
        return `$${params.length}`;
      });

      conditions.push(`${Nft.SPENDER} in (${paramsForCondition})`);
    }
```
