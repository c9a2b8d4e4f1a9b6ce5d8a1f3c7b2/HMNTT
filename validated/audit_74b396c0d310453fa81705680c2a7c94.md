Based on my code investigation, I can verify the key technical claims. Here is my assessment:

---

Audit Report

## Title
Unauthenticated High-Frequency Flooding of `/contracts/results` Causes Sustained Database Load via Absent Rate Limiting and Disabled Range Enforcement

## Summary
The `GET /api/v1/contracts/results` endpoint accepts arbitrary timestamp range filters from unauthenticated callers, triggers up to three concurrent database queries per request, and has no per-IP rate limiting in the REST layer. The timestamp range validation is explicitly skipped via `validateRange=false`, and the only bounding mechanism (`bindTimestampRange`) is disabled by default. This allows any caller to sustain high-frequency requests that exhaust the shared PostgreSQL connection pool.

## Finding Description

**Route registration** — `rest/routes/contractRoute.js` line 19 registers the endpoint with no authentication or rate-limit middleware: [1](#0-0) 

The `extendExpress` wrapper adds only async error-handling logic and no rate limiting: [2](#0-1) 

**Handler fires three DB queries** — `contractController.js` lines 1072–1086 first queries contract results, then fires two more concurrent queries via `Promise.all`: [3](#0-2) 

**Timestamp range validation is bypassed** — `optimizeTimestampFilters` at line 387 calls `parseTimestampFilters` with the sixth argument (`validateRange`) set to `false`, meaning the `maxTimestampRangeNs` guard in `parseTimestampFilters` is never reached for this call path: [4](#0-3) 

**No REST-layer rate limiting** — A search across all `rest/**/*.js` files for `rateLimit`, `rate-limit`, and `throttle` returns only a single match in a test utility file (`rest/__tests__/integrationUtils.js`), confirming no production rate-limiting middleware exists in the Node.js REST layer. [5](#0-4) 

## Impact Explanation
Each unauthenticated request with a wide or open-ended timestamp range (e.g., `timestamp=gte:0`) causes up to three concurrent SQL queries against the shared PostgreSQL instance. Sustained flooding exhausts the DB connection pool, increases query latency for the importer, and can stall record-file ingestion — directly degrading the node's ability to keep up with the gossip stream. As a side effect, the attacker gains full enumeration of all contract transaction history. [6](#0-5) 

## Likelihood Explanation
No privileges, API keys, or special knowledge are required. Any internet-accessible mirror node is reachable. The attack is trivially scriptable with a loop of `curl` or `ab` commands using sliding `timestamp=gte:X&timestamp=lte:Y` windows. The absence of per-IP rate limiting means a single client can sustain the load indefinitely. The default-off `bindTimestampRange` means most production deployments are affected unless operators have explicitly enabled it. [7](#0-6) 

## Recommendation
1. **Add application-level rate limiting** to the REST layer (e.g., `express-rate-limit`) scoped per IP, applied globally or at least to resource-intensive endpoints like `/contracts/results`.
2. **Enable `bindTimestampRange` by default** or enforce a maximum timestamp range on the `optimizeTimestampFilters` call path by passing `validateRange=true` (or a dedicated range cap) to `parseTimestampFilters`.
3. **Cap the result set** more aggressively for unauthenticated callers to reduce per-request DB cost.
4. Consider infrastructure-level mitigations (CDN, WAF, load-balancer rate limiting) as a defense-in-depth layer.

## Proof of Concept
```bash
# Flood the endpoint with wide open-ended timestamp ranges
while true; do
  curl -s "https://<mirror-node>/api/v1/contracts/results?timestamp=gte:0&limit=100" &
done
```
Each iteration triggers three concurrent SQL queries (contract results + Ethereum transactions + record file block details). With sufficient concurrency, the PostgreSQL connection pool is saturated and importer latency rises measurably. [8](#0-7)

### Citations

**File:** rest/routes/contractRoute.js (L9-19)
```javascript
const router = extendExpress(express.Router());

const resource = 'contracts';
router.getExt('/', ContractController.getContracts);
router.getExt('/:contractId', ContractController.getContractById);
router.getExt('/:contractId/results', ContractController.getContractResultsById);
router.getExt('/:contractId/state', ContractController.getContractStateById);
router.getExt('/:contractId/results/logs', ContractController.getContractLogsById);
// must add after '/:contractId/results/logs' for proper conflict resolution
router.getExt('/:contractId/results/:consensusTimestamp', ContractController.getContractResultsByTimestamp);
router.getExt('/results', ContractController.getContractResults);
```

**File:** rest/extendExpress.js (L6-16)
```javascript
const extendExpress = (app) => {
  const methods = ['get', 'use'];
  for (const method of methods) {
    app[`${method}Ext`] = function () {
      const args = wrapArgs(arguments);
      return app[method].apply(app, args);
    };
  }

  return app;
};
```

**File:** rest/extendExpress.js (L31-58)
```javascript
const wrap = (fn) => {
  const isErrorHandler = fn.length === 4;
  const wrapped = async function () {
    // Ensure next function is only ran once
    arguments[2 + isErrorHandler] = _once(arguments[2 + isErrorHandler]);
    try {
      const promise = fn.apply(null, arguments);
      if (promise && typeof promise.then === 'function') {
        await promise;
        arguments[1 + isErrorHandler].headersSent ? null : arguments[2 + isErrorHandler]();
      }
    } catch (err) {
      arguments[1 + isErrorHandler].headersSent ? null : arguments[2 + isErrorHandler](err);
    }
  };

  Object.defineProperty(wrapped, 'length', {
    // Length has to be set for express to recognize error handlers as error handlers
    value: isErrorHandler ? 4 : 3,
  });

  Object.defineProperty(wrapped, 'name', {
    // Define a name for stack traces
    value: isErrorHandler ? 'wrappedErrorHandler' : 'wrappedMiddleware',
  });

  return wrapped;
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

**File:** rest/controllers/contractController.js (L1050-1086)
```javascript
  getContractResults = async (req, res) => {
    const filters = utils.buildAndValidateFilters(
      req.query,
      acceptedContractResultsParameters,
      contractResultsFilterValidityChecks
    );

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);

    const response = {
      results: [],
      links: {
        next: null,
      },
    };
    res.locals[responseDataLabel] = response;
    const {conditions, params, order, limit, skip, next} = await this.extractContractResultsByIdQuery(filters);
    if (skip) {
      return;
    }

    const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
    if (rows.length === 0) {
      return;
    }

    const payers = [];
    const timestamps = [];
    rows.forEach((row) => {
      payers.push(row.payerAccountId);
      timestamps.push(row.consensusTimestamp);
    });
    const [ethereumTransactionMap, recordFileMap] = await Promise.all([
      ContractService.getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps),
      RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps),
    ]);
```
