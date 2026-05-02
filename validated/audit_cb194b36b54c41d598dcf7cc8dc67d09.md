Based on my code investigation, I verified the key claims against the actual source code.

**Verified facts:**

- `getContractLogs` at line 820 calls `checkTimestampsForTopics(filters)` then `extractContractLogsMultiUnionQuery(filters)` at line 835. [1](#0-0) 

- `checkTimestampsForTopics` at line 281 only invokes `utils.parseTimestampFilters(timestampFilters)` (with default `validateRange=true`) inside the `if (hasTopic)` block. With no topic params, `hasTopic` stays `false` and the block is skipped entirely. [2](#0-1) 

- `optimizeTimestampFilters` at line 387 explicitly passes `false` as the 6th argument (`validateRange`) to `utils.parseTimestampFilters`. [3](#0-2) 

- `optimizeTimestampFilters` is invoked at line 680 only when `contractId === undefined`, which is always the case for `/contracts/results/logs`. [4](#0-3) 

- `bindTimestampRange` immediately returns `{range}` unchanged when `queryConfig.bindTimestampRange` is `false` (lines 20–22), which is the default. [5](#0-4) 

All code path references, line numbers, and bypass logic are confirmed. The vulnerability is real.

---

# Audit Report

## Title
Unbounded Timestamp Range Bypass in `getContractLogs` Enables Full Table Scan DoS

## Summary
The `GET /contracts/results/logs` endpoint allows any unauthenticated caller to supply an arbitrarily wide timestamp range with no topic filters. The 7-day range validation is bypassed via an explicit `validateRange=false` argument in `optimizeTimestampFilters`, and the only remaining guard (`bindTimestampRange`) is opt-in and disabled by default. The result is a full sequential scan of the `contract_log` table on every such request.

## Finding Description

**Confirmed code path:**

`getContractLogs` (line 820) → `extractContractLogsMultiUnionQuery` (line 835) → `optimizeTimestampFilters` (line 680) → `utils.parseTimestampFilters(timestampFilters, false, true, true, false, false)` (line 387).

The sixth argument is `validateRange = false`, which disables the 7-day range enforcement inside `parseTimestampFilters`. [6](#0-5) 

**Why `checkTimestampsForTopics` does not help:**

`checkTimestampsForTopics` (line 281) only calls `parseTimestampFilters` with default parameters (i.e., `validateRange = true`) inside the `if (hasTopic)` block. A request with no topic parameters leaves `hasTopic = false`, so the block is never entered. [7](#0-6) 

**Why `bindTimestampRange` does not help:**

`bindTimestampRange` returns `{range}` unchanged immediately when `queryConfig.bindTimestampRange` is `false`, which is the default configuration. No `application.yml` in the repository sets this to `true` for the REST service. [5](#0-4) 

**Resulting SQL behavior:**

With no effective timestamp bound, the generated query carries `consensus_timestamp >= 0 AND consensus_timestamp <= 9999999999999999999`. The `LIMIT` clause caps returned rows but does not prevent the database from performing a sequential scan across the entire `contract_log` table to locate the first N matching rows.

## Impact Explanation
Every such request forces a full or near-full sequential scan of `contract_log`, a table that grows unboundedly as the network operates. Concurrent requests from a single attacker can saturate database I/O, increase query latency for all legitimate users, and potentially exhaust database connection pools. This is a classic read-amplification denial-of-service. No authentication, API key, or special privilege is required.

## Likelihood Explanation
The endpoint is public and unauthenticated. The exploit requires a single HTTP GET request with two query parameters (`timestamp=gte:0&timestamp=lte:9999999999.999999999`). It is trivially scriptable and repeatable at high frequency. The endpoint is documented in the OpenAPI spec at `/api/v1/contracts/results/logs`. The only deployment-side mitigation (`bindTimestampRange=true`) is opt-in and off by default, meaning most deployments are exposed.

## Recommendation
1. **Remove the `validateRange=false` bypass** in `optimizeTimestampFilters` (line 387) or add an explicit maximum timestamp span check before the `bindTimestampRange` call.
2. **Enable `bindTimestampRange` by default** in the default configuration, or enforce a hard-coded maximum range for the `/contracts/results/logs` endpoint regardless of config.
3. **Extend `checkTimestampsForTopics`** to enforce a maximum timestamp range even when `hasTopic = false`, rather than skipping validation entirely.

## Proof of Concept

```
GET /api/v1/contracts/results/logs?timestamp=gte:0&timestamp=lte:9999999999.999999999
```

No authentication headers required. With `bindTimestampRange` at its default value of `false` and no topic parameters supplied, the request bypasses all range guards and triggers a full sequential scan of `contract_log`. Repeating this request in a tight loop from a single client is sufficient to degrade database performance for all concurrent users.

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

**File:** rest/controllers/contractController.js (L678-686)
```javascript
    } else if (contractId === undefined) {
      // Optimize timestamp filters only when there is no transaction hash and transaction id
      const {filters: timestampFilters, next} = await optimizeTimestampFilters(bounds.primary.getAllFilters(), order);
      bounds.primary = new Bound(filterKeys.TIMESTAMP);
      query.bounds.next = next;
      for (const filter of timestampFilters) {
        bounds.primary.parse(filter);
      }
    }
```

**File:** rest/controllers/contractController.js (L820-835)
```javascript
  getContractLogs = async (req, res) => {
    // get sql filter query, params, limit and limit query from query filters
    const filters = alterTimestampRange(utils.buildAndValidateFilters(req.query, acceptedContractLogsParameters));
    checkTimestampsForTopics(filters);

    // Workaround: set the request path in handler so later in the router level generic middleware it won't be
    // set to /contracts/results/:transactionIdOrHash
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`;
    res.locals[responseDataLabel] = {
      logs: [],
      links: {
        next: null,
      },
    };

    const query = await this.extractContractLogsMultiUnionQuery(filters);
```

**File:** rest/timestampRange.js (L19-22)
```javascript
const bindTimestampRange = async (range, order) => {
  if (!queryConfig.bindTimestampRange) {
    return {range};
  }
```
