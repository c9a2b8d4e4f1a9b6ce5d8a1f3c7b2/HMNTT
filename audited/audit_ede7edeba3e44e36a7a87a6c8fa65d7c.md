### Title
Unauthenticated UNION Query DoS via Timestamp-Triggered entity/entity_history Scan in GET /contracts/:contractId

### Summary
The `getContractById()` handler in `rest/controllers/contractController.js` accepts a `timestamp` query parameter from any unauthenticated user. When supplied, `getContractByIdOrAddressContractEntityQuery()` unconditionally emits a UNION query spanning both the `entity` and `entity_history` tables. Because the REST API has no per-IP rate limiting, an attacker can flood the endpoint with varying timestamp values and a valid EVM address, sustaining high-cost DB queries that exhaust the connection pool and degrade service for all users.

### Finding Description

**Exact code path:**

`getContractById()` at [1](#0-0)  calls `extractContractIdAndFiltersFromValidatedRequest()` which accepts `acceptedContractByIdParameters` — defined as `new Set([filterKeys.TIMESTAMP])` at [2](#0-1)  — meaning `timestamp` is a fully supported, publicly accessible query parameter.

The extracted timestamp filters are passed to `utils.extractTimestampRangeConditionFilters()`, which converts them into `timestampConditions`. These are then forwarded to `getContractByIdOrAddressContractEntityQuery()`:

```
const {conditions: timestampConditions, params: timestampParams} =
  utils.extractTimestampRangeConditionFilters(filters);

const {query, params} = getContractByIdOrAddressContractEntityQuery({
  timestampConditions,
  timestampParams,
  contractIdParam,
});
```

Inside `getContractByIdOrAddressContractEntityQuery()`, the UNION branch is triggered by a single condition: [3](#0-2) 

```js
if (timestampConditions.length !== 0) {
  tableUnionQueries.push(
    'union',
    getContractByIdOrAddressQueryForTable(Entity.historyTableName, conditions),
    `order by ${Entity.TIMESTAMP_RANGE} desc`,
    `limit 1`
  );
}
```

When the contractId is a 40-character hex EVM address, `contractIdParamParts.create2_evm_address` is set and the condition becomes `e.evm_address = $3` on both `entity` and `entity_history`. The resulting query is:

```sql
SELECT <fields> FROM entity e LEFT JOIN contract c ON e.id = c.id
WHERE e.type = 'CONTRACT' AND c.timestamp_range && $1 AND e.evm_address = $3
UNION
SELECT <fields> FROM entity_history e LEFT JOIN contract c ON e.id = c.id
WHERE e.type = 'CONTRACT' AND c.timestamp_range && $1 AND e.evm_address = $3
ORDER BY timestamp_range DESC LIMIT 1
```

**Root cause:** The UNION across `entity_history` (a potentially very large historical table) is unconditionally triggered by any non-empty `timestampConditions`, with no guard, no caching, and no rate limiting at the REST layer.

**Why checks fail:**

- Input validation only checks timestamp format and EVM address format — both trivially satisfied. [4](#0-3) 
- The REST `server.js` applies no per-IP rate limiting middleware — only `cors`, `compression`, `authHandler` (optional Basic Auth for limit overrides), and optional Redis response caching. [5](#0-4) 
- The throttle/rate-limit infrastructure found in the codebase applies exclusively to the `web3` Java service (contract call simulation), not to the REST Node.js API. [6](#0-5) 
- The optional Redis response cache (`responseCacheCheckHandler`) would only help for identical requests; an attacker using varying timestamp values (e.g., `timestamp=lte:<incrementing_value>`) bypasses it entirely. [7](#0-6) 

### Impact Explanation

Each request with a timestamp parameter forces a UNION across `entity` and `entity_history`. The `entity_history` table accumulates all historical entity states and grows unboundedly over time. The range-overlap operator (`&&`) on `timestamp_range` combined with an `evm_address` equality filter on a non-primary-key column requires a sequential or index scan on both tables, followed by a UNION deduplication sort. Sustained concurrent requests exhaust the PostgreSQL connection pool, increase DB CPU/IO, and cause latency spikes or timeouts for all other API consumers. This is a classic resource exhaustion DoS with no authentication barrier.

### Likelihood Explanation

The attack requires zero privileges, zero on-chain assets, and only knowledge of the public API. Any 40-character hex string is a syntactically valid EVM address (the query will simply return 0 rows, but the DB work is still performed). The attacker can script thousands of requests per second from a single machine or botnet. The varying-timestamp trick trivially defeats any response-level caching. This is highly repeatable and requires no special tooling beyond `curl` or `ab`.

### Recommendation

1. **Add per-IP rate limiting** to the REST Express application (e.g., `express-rate-limit`) specifically for the `/contracts/:contractId` route or globally.
2. **Add a DB statement timeout** for the REST pool (if not already configured) to bound the maximum duration of any single UNION query.
3. **Consider caching** the result of `getContractByIdOrAddressContractEntityQuery` at the application layer (e.g., short-lived in-memory or Redis cache keyed on `contractId + timestampConditions`) to serve repeated identical queries without hitting the DB.
4. **Restrict timestamp filter cardinality**: enforce that at most one timestamp filter is accepted per request for this endpoint (already partially enforced by `buildAndValidateFilters`, but verify the max repeated query parameter limit applies here).

### Proof of Concept

```bash
# Step 1: Identify any valid EVM address format (does not need to exist on-chain)
EVM_ADDR="70f2b2914a2a4b783faefb75f459a580616fcb5e"

# Step 2: Send concurrent requests with varying timestamps to bypass cache
# and force repeated UNION queries across entity + entity_history
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/contracts/0x${EVM_ADDR}?timestamp=lte:${i}000000000" &
done
wait

# Each request triggers:
# SELECT ... FROM entity WHERE e.evm_address=$3 AND c.timestamp_range && $1
# UNION
# SELECT ... FROM entity_history WHERE e.evm_address=$3 AND c.timestamp_range && $1
# ORDER BY timestamp_range DESC LIMIT 1
#
# Result: DB connection pool saturation, elevated CPU/IO on PostgreSQL,
# degraded response times for all legitimate API consumers.
```

### Citations

**File:** rest/controllers/contractController.js (L193-202)
```javascript
  const tableUnionQueries = [getContractByIdOrAddressQueryForTable(Entity.tableName, conditions)];
  if (timestampConditions.length !== 0) {
    // if there is timestamp condition, union the result from both tables
    tableUnionQueries.push(
      'union',
      getContractByIdOrAddressQueryForTable(Entity.historyTableName, conditions),
      `order by ${Entity.TIMESTAMP_RANGE} desc`,
      `limit 1`
    );
  }
```

**File:** rest/controllers/contractController.js (L340-344)
```javascript
const getAndValidateContractIdRequestPathParam = (req) => {
  const contractIdValue = req.params.contractId;
  validateContractIdParam(contractIdValue);
  return utils.stripHexPrefix(contractIdValue);
};
```

**File:** rest/controllers/contractController.js (L707-724)
```javascript
  getContractById = async (req, res) => {
    if (utils.conflictingPathParam(req, 'contractId', 'results')) {
      return;
    }

    const {filters, contractId: contractIdParam} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractByIdParameters
    );

    const {conditions: timestampConditions, params: timestampParams} =
      utils.extractTimestampRangeConditionFilters(filters);

    const {query, params} = getContractByIdOrAddressContractEntityQuery({
      timestampConditions,
      timestampParams,
      contractIdParam,
    });
```

**File:** rest/controllers/contractController.js (L1332-1332)
```javascript
const acceptedContractByIdParameters = new Set([filterKeys.TIMESTAMP]);
```

**File:** rest/server.js (L67-98)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
