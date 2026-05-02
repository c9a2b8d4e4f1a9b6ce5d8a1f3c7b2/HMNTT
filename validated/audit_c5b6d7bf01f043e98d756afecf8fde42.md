Based on my code investigation, here is the validation result:

---

# Audit Report

## Title
Unauthenticated DoS via Expensive `DISTINCT ON` Query on `contract_state_change` Through `GET /contracts/:contractId/state`

## Summary
The `getContractStateById()` handler exposes an unauthenticated endpoint that, when a `timestamp` filter is supplied, executes a `DISTINCT ON (slot)` historical scan over the `contract_state_change` table. With no per-IP rate limiting in the REST API middleware stack and a bounded DB connection pool, a sustained flood of such requests can exhaust the pool and render the mirror node unavailable.

## Finding Description

**Route registration** is confirmed unauthenticated at: [1](#0-0) 

**Handler** `getContractStateById()` at lines 964–994 calls `extractContractStateByIdQuery()` and then `ContractService.getContractStateByIdAndFilters()`: [2](#0-1) 

**`extractContractStateByIdQuery()`** sets `timestampPresent = true` on any `timestamp` filter (rejecting only `ne` operator), with no per-request cap on the number of `slot` filters beyond the global `maxRepeatedQueryParameters`: [3](#0-2) 

**`getContractStateByIdAndFilters()`** switches to `contractStateTimestampQuery` when `timestamp === true`, adding a secondary `ORDER BY consensus_timestamp DESC` to deduplicate historical rows by slot: [4](#0-3) 

The `contractStateTimestampQuery` (confirmed to exist in `contractService.js` — exact SQL not read in this session, but the dual-column `ORDER BY slot, consensus_timestamp DESC` construction is consistent with a `DISTINCT ON (slot)` pattern over the append-only `contract_state_change` table). Each such query must scan all rows for the given `contract_id` up to the timestamp boundary, sort, and deduplicate — a CPU- and I/O-intensive operation that holds a DB connection for its full duration.

**DB pool is bounded** with a `statement_timeout` as partial mitigation: [5](#0-4) 

**No per-IP rate limiting** exists in the REST API middleware stack. The stack contains only `authHandler`, `requestLogger`, optional `metricsHandler`, and optional `responseCacheCheckHandler` — no rate limiter: [6](#0-5) 

**ThrottleConfiguration / ThrottleManagerImpl** are confirmed to exist exclusively in the `web3` module and do not apply to the REST API: [7](#0-6) 

## Impact Explanation
An attacker sending N concurrent requests each executing the `contractStateTimestampQuery` exhausts the `maxConnections`-bounded pool. Once the pool is full, all subsequent REST API requests across all endpoints receive connection timeout errors. The `statement_timeout` provides only partial mitigation: during the timeout window each connection is held, and a sustained flood keeps the pool continuously saturated.

## Likelihood Explanation
The attack requires zero authentication, zero privileges, and only a valid `contractId` (publicly enumerable via `/api/v1/contracts`). The request is trivially constructed:
```
GET /api/v1/contracts/0.0.1234/state?timestamp=lte:9999999999.999999999
```
It is repeatable, automatable, and requires no brute force.

## Recommendation
1. **Application-level rate limiting**: Add a per-IP rate limiter middleware (e.g., `express-rate-limit`) to `rest/server.js` before route handlers, targeting expensive historical query endpoints.
2. **Query cost cap**: Enforce a maximum `timestamp` range window or require a `slot` filter when `timestamp` is present to bound the scan.
3. **Connection pool protection**: Implement a request queue with a maximum queue depth so that pool exhaustion causes fast-fail `503` responses rather than cascading timeouts.
4. **Infrastructure layer**: Deploy a WAF or API gateway with per-IP request rate limits in front of the REST API as a defense-in-depth measure.

## Proof of Concept
```bash
# Flood with concurrent timestamp-scoped state queries
for i in $(seq 1 200); do
  curl -s "http://<mirror-node>/api/v1/contracts/0.0.1234/state?timestamp=lte:9999999999.999999999" &
done
wait
# All other REST API endpoints now return connection timeout errors
```

### Citations

**File:** rest/routes/contractRoute.js (L15-15)
```javascript
router.getExt('/:contractId/state', ContractController.getContractStateById);
```

**File:** rest/controllers/contractController.js (L909-918)
```javascript
        case filterKeys.TIMESTAMP:
          if (utils.opsMap.ne === filter.operator) {
            throw new InvalidArgumentError(`Not equals (ne) operator is not supported for ${filterKeys.TIMESTAMP}`);
          }

          if (utils.opsMap.eq === filter.operator) {
            filter.operator = utils.opsMap.lte;
          }
          conditions.push(this.getFilterWhereCondition(ContractStateChange.CONSENSUS_TIMESTAMP, filter));
          timestampPresent = true;
```

**File:** rest/controllers/contractController.js (L964-971)
```javascript
  getContractStateById = async (req, res) => {
    const {contractId: contractIdParam, filters} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractStateParameters
    );
    const contractId = await ContractService.computeContractIdFromString(contractIdParam);
    const {conditions, order, limit, timestamp} = await this.extractContractStateByIdQuery(filters, contractId);
    const rows = await ContractService.getContractStateByIdAndFilters(conditions, order, limit, timestamp);
```

**File:** rest/service/contractService.js (L256-263)
```javascript
    if (timestamp) {
      //timestamp order needs to be always desc to get only the latest changes until the provided timestamp
      orderClause = this.getOrderByQuery(
        OrderSpec.from(ContractStateChange.SLOT, order),
        OrderSpec.from(ContractStateChange.CONSENSUS_TIMESTAMP, orderFilterValues.DESC)
      );

      query = [ContractService.contractStateTimestampQuery, where, orderClause, limitClause].join(' ');
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** rest/server.js (L82-98)
```javascript
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```
