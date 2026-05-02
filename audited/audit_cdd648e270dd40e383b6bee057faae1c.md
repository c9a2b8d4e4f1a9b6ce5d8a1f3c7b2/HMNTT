### Title
Unbounded Timestamp Range Bypass in `getContractLogs` Enables Full Table Scan DoS

### Summary
The `GET /contracts/results/logs` endpoint handled by `getContractLogs()` in `rest/controllers/contractController.js` allows any unauthenticated user to supply an arbitrarily wide timestamp range (e.g., `timestamp=gte:0&timestamp=lte:9999999999.999999999`) without topics. The 7-day range validation that exists in `parseTimestampFilters` is explicitly disabled in the `optimizeTimestampFilters` helper, and the only other guard (`bindTimestampRange`) is an opt-in config flag that defaults to `false`. This causes the generated SQL to scan the entire `contract_log` table, consuming massive DB I/O and degrading query performance for all users.

### Finding Description

**Code path:**

`getContractLogs` (line 820) → `extractContractLogsMultiUnionQuery(filters)` (line 835) → `optimizeTimestampFilters(bounds.primary.getAllFilters(), order)` (line 680) → `utils.parseTimestampFilters(timestampFilters, false, true, true, false, false)` (line 387).

The sixth argument to `parseTimestampFilters` is `validateRange`, and it is explicitly passed as `false`: [1](#0-0) 

Inside `parseTimestampFilters`, the 7-day range enforcement block is: [2](#0-1) 

Because `validateRange = false`, this block is never reached. The only remaining guard is `bindTimestampRange`: [3](#0-2) 

`bindTimestampRange` immediately returns `{range}` unchanged when `queryConfig.bindTimestampRange` is `false` (line 20–22), which is the default. No `application.yml` in the repo sets this to `true` for the REST service.

**Why `checkTimestampsForTopics` does not help:**

`checkTimestampsForTopics` (line 281) calls `parseTimestampFilters` with default parameters (i.e., `validateRange = true`) and enforces the 7-day limit — but only when `hasTopic = true`: [4](#0-3) 

A request with no topic parameters sets `hasTopic = false`, so the block is skipped entirely. The attacker simply omits all topic parameters.

**Resulting SQL:** The `getContractLogsQuery` in `ContractService` builds a query with `consensus_timestamp >= 0 AND consensus_timestamp <= 9999999999999999999` and a `LIMIT` clause. The LIMIT caps returned rows but does not prevent the DB from performing a sequential scan across the entire `contract_log` table to find the first N matching rows. [5](#0-4) 

### Impact Explanation
Every such request forces a full or near-full sequential scan of `contract_log`, a table that grows unboundedly as the network operates. Concurrent requests from a single attacker (or a small botnet) can saturate DB I/O, increase query latency for all legitimate users, and potentially exhaust DB connection pools. This is a classic read-amplification DoS. No authentication, API key, or special privilege is required.

### Likelihood Explanation
The endpoint is public and unauthenticated. The exploit requires a single HTTP GET request with two query parameters. It is trivially scriptable and repeatable at high frequency. Any user who discovers the API (documented in the OpenAPI spec at `/api/v1/contracts/results/logs`) can execute it. The only deployment-side mitigation (`bindTimestampRange=true`) is opt-in and off by default, meaning most deployments are exposed.

### Recommendation
1. **Remove `validateRange = false`** from the `optimizeTimestampFilters` call, or add an explicit range-width check before calling `bindTimestampRange`. The 7-day cap enforced by `parseTimestampFilters` when `validateRange = true` should apply to all callers, not just topic-bearing requests.
2. **Enable `bindTimestampRange` by default** in the default configuration, or make it mandatory for the `/contracts/results/logs` endpoint.
3. **Apply rate limiting** at the API gateway layer for this endpoint as a defense-in-depth measure.

### Proof of Concept

```
# No authentication required. No topics needed.
curl "https://<mirror-node-host>/api/v1/contracts/results/logs?timestamp=gte:0&timestamp=lte:9999999999.999999999&limit=100"
```

**Steps:**
1. Send the above request to any deployed mirror node REST API.
2. Observe that the request is accepted (HTTP 200) with no 400 validation error.
3. Monitor DB I/O — the `contract_log` table is scanned from timestamp 0 to the maximum possible value.
4. Repeat in a tight loop (e.g., 50 concurrent connections) to saturate DB read I/O and degrade all concurrent log queries.

### Citations

**File:** rest/controllers/contractController.js (L281-306)
```javascript
const checkTimestampsForTopics = (filters) => {
  let hasTopic = false;
  const timestampFilters = [];
  for (const filter of filters) {
    switch (filter.key) {
      case filterKeys.TOPIC0:
      case filterKeys.TOPIC1:
      case filterKeys.TOPIC2:
      case filterKeys.TOPIC3:
        hasTopic = true;
        break;
      case filterKeys.TIMESTAMP:
        timestampFilters.push(filter);
        break;
      default:
        break;
    }
  }
  if (hasTopic) {
    try {
      utils.parseTimestampFilters(timestampFilters);
    } catch (e) {
      throw new InvalidArgumentError(`Cannot search topics without a valid timestamp range: ${e.message}`);
    }
  }
};
```

**File:** rest/controllers/contractController.js (L384-405)
```javascript
const optimizeTimestampFilters = async (timestampFilters, order) => {
  const filters = [];

  const {range, eqValues, neValues} = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
  if (range?.isEmpty()) {
    return {filters};
  }

  const {range: optimizedRange, next} = eqValues.length === 0 ? await bindTimestampRange(range, order) : {range};
  if (optimizedRange?.begin) {
    filters.push({key: filterKeys.TIMESTAMP, operator: utils.opsMap.gte, value: optimizedRange.begin});
  }

  if (optimizedRange?.end) {
    filters.push({key: filterKeys.TIMESTAMP, operator: utils.opsMap.lte, value: optimizedRange.end});
  }

  eqValues.forEach((value) => filters.push({key: filterKeys.TIMESTAMP, operator: utils.opsMap.eq, value}));
  neValues.forEach((value) => filters.push({key: filterKeys.TIMESTAMP, operator: utils.opsMap.ne, value}));

  return {filters, next};
};
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

**File:** rest/timestampRange.js (L19-38)
```javascript
const bindTimestampRange = async (range, order) => {
  if (!queryConfig.bindTimestampRange) {
    return {range};
  }

  const {maxTransactionsTimestampRangeNs} = queryConfig;
  const boundRange = Range(range?.begin ?? (await getFirstTransactionTimestamp()), range?.end ?? nowInNs(), '[]');
  if (boundRange.end - boundRange.begin + 1n <= maxTransactionsTimestampRangeNs) {
    return {range: boundRange};
  }

  let next;
  if (order === orderFilterValues.DESC) {
    next = boundRange.begin = boundRange.end - maxTransactionsTimestampRangeNs + 1n;
  } else {
    next = boundRange.end = boundRange.begin + maxTransactionsTimestampRangeNs - 1n;
  }

  return {range: boundRange, next: nsToSecNs(next)};
};
```

**File:** rest/service/contractService.js (L323-368)
```javascript
  getContractLogsQuery({lower, inner, upper, params, conditions, order, limit}) {
    params.push(limit);
    const orderClause = super.getOrderByQuery(
      OrderSpec.from(ContractLog.getFullName(ContractLog.CONSENSUS_TIMESTAMP), order),
      OrderSpec.from(ContractLog.getFullName(ContractLog.INDEX), order)
    );
    const orderClauseNoAlias = super.getOrderByQuery(
      OrderSpec.from(ContractLog.CONSENSUS_TIMESTAMP, order),
      OrderSpec.from(ContractLog.INDEX, order)
    );
    const limitClause = super.getLimitQuery(params.length);

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

    return [sqlQuery, params];
  }
```
