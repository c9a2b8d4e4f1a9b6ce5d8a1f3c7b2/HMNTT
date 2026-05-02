### Title
Unauthenticated Timestamp Parameter Triggers Expensive `entity_history` UNION Query in `getContractById`, Enabling Denial-of-Service

### Summary
The `getContractById` handler in `rest/controllers/contractController.js` accepts a `timestamp` query parameter from any unauthenticated user. When present, it unconditionally switches from a cheap single-table lookup on `entity` to a significantly more expensive UNION query that also scans `entity_history`. There is no rate limiting, authentication, or query cost mitigation, allowing an attacker to repeatedly trigger the expensive path and exhaust database resources.

### Finding Description

**Route registration** (`rest/routes/contractRoute.js`, line 13):
```
router.getExt('/:contractId', ContractController.getContractById);
```
No authentication middleware is applied.

**Handler** (`rest/controllers/contractController.js`, lines 707–737):
```js
getContractById = async (req, res) => {
  const {filters, contractId: contractIdParam} = extractContractIdAndFiltersFromValidatedRequest(
    req, acceptedContractByIdParameters          // timestamp is an accepted parameter
  );
  const {conditions: timestampConditions, params: timestampParams} =
    utils.extractTimestampRangeConditionFilters(filters);  // extracts user-supplied timestamp

  const {query, params} = getContractByIdOrAddressContractEntityQuery({
    timestampConditions, timestampParams, contractIdParam,
  });
  const {rows} = await pool.queryQuietly(query, params);
  ...
};
```

**Query builder** (`rest/controllers/contractController.js`, lines 179–208):
```js
const getContractByIdOrAddressContractEntityQuery = ({timestampConditions, timestampParams, contractIdParam}) => {
  ...
  const tableUnionQueries = [getContractByIdOrAddressQueryForTable(Entity.tableName, conditions)];
  if (timestampConditions.length !== 0) {          // ← any timestamp triggers this branch
    tableUnionQueries.push(
      'union',
      getContractByIdOrAddressQueryForTable(Entity.historyTableName, conditions),  // entity_history scan
      `order by ${Entity.TIMESTAMP_RANGE} desc`,
      `limit 1`
    );
  }
  return { query: tableUnionQueries.join('\n'), params };
};
```

**Root cause**: The sole gate for the expensive path is `timestampConditions.length !== 0` (line 194). Any syntactically valid timestamp value supplied by an unauthenticated user satisfies this condition. The `entity_history` table accumulates every historical state of every entity on the network and grows unboundedly; a UNION scan over it is orders of magnitude more expensive than the single-table `entity` lookup. The query is confirmed by the test suite to produce a full UNION + `ORDER BY timestamp_range DESC LIMIT 1` plan when a timestamp is present (test file `rest/__tests__/controllers/contractController.test.js`, lines 196–249).

**Existing checks reviewed and found insufficient**:
- `validateContractIdParam` validates only the contract ID format, not the timestamp.
- `utils.buildAndValidateFilters` validates timestamp *format* (e.g., `seconds.nanoseconds`), not whether the caller is authorized to use the historical path.
- No rate limiting, no authentication, no query timeout, and no caching layer is applied to this endpoint in the reviewed code.

### Impact Explanation
An attacker who sends a high volume of requests such as `GET /api/v1/contracts/0.0.1?timestamp=lte:9999999999` forces the database to execute a UNION across `entity` and `entity_history` for every request. As `entity_history` grows with network activity, each such query becomes progressively more expensive. Sustained flooding can exhaust database CPU, connection pool slots, or I/O bandwidth, degrading or denying service to all API consumers. Because the endpoint returns contract metadata used by wallets and dApps, availability impact is broad.

### Likelihood Explanation
The precondition is zero: no account, API key, or special knowledge is required. The trigger is a single well-known query parameter documented in the API spec. The attack is trivially scriptable with any HTTP client (`curl`, `ab`, `wrk`). The cost asymmetry between the two code paths makes even a modest request rate (tens of requests per second) potentially impactful on a large network node.

### Recommendation
1. **Rate-limit the historical path**: Apply a stricter per-IP rate limit specifically when `timestamp` is present, separate from the general API rate limit.
2. **Add a statement timeout**: Set a short `statement_timeout` (e.g., 2–5 s) on the database connection used for this query so runaway UNION scans are killed automatically.
3. **Index coverage**: Ensure `entity_history` has a composite index on `(id, timestamp_range)` (or `(evm_address, timestamp_range)` for EVM lookups) so the UNION leg uses an index scan rather than a sequential scan.
4. **Consider caching**: Cache historical contract lookups (immutable once the timestamp is in the past) with a short TTL to absorb repeated identical queries.

### Proof of Concept
```bash
# Single request demonstrating the expensive path
curl "https://<mirror-node-host>/api/v1/contracts/0.0.1?timestamp=lte:9999999999"

# DoS loop (no credentials required)
while true; do
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/contracts/0.0.1?timestamp=lte:9999999999" &
done
# Observe database CPU/connection exhaustion on the mirror node
```

The request requires no authentication, no special headers, and no prior knowledge beyond a valid contract ID (which is publicly enumerable from the same API).