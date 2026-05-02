### Title
Unbounded Sequential DB Lookups via Multiple `from` EVM Address Parameters in `extractContractResultsByIdQuery`

### Summary
The `extractContractResultsByIdQuery` function in `rest/controllers/contractController.js` iterates over all `from` filters in a `for...of` loop and issues a sequential `await EntityService.getEncodedId()` DB call for each filter value that is a valid EVM address. Because the `from` parameter is repeatable up to the global `maxRepeatedQueryParameters` limit (default: **100**), an unauthenticated attacker can force up to 100 sequential DB lookups per single HTTP request. No authentication or special privilege is required to reach either `/api/v1/contracts/results` or `/api/v1/contracts/:contractId/results`.

### Finding Description

**Exact code path:**

`rest/controllers/contractController.js`, `extractContractResultsByIdQuery`, lines 439–454:

```js
for (const filter of filters) {
  switch (filter.key) {
    case filterKeys.FROM:
      // Evm addresses are not parsed by utils.buildAndValidateFilters,
      // so they are converted to encoded ids here.
      if (EntityId.isValidEvmAddress(filter.value)) {
        filter.value = await EntityService.getEncodedId(filter.value); // ← DB hit per value
      }
      ...
``` [1](#0-0) 

`EntityService.getEncodedId` calls `getEntityIdFromEvmAddress`, which executes a raw SQL query against the `entity` table for each invocation:

```js
static entityFromEvmAddressQuery = `select ${Entity.ID}
    from ${Entity.tableName}
    where ${Entity.DELETED} <> true
      and ${Entity.EVM_ADDRESS} = $1`;
``` [2](#0-1) 

There is no deduplication, batching, or in-process caching inside `EntityService.getEncodedId` or `getEntityIdFromEvmAddress`.

**Root cause / failed assumption:** The code assumes `from` will be supplied at most once per request. In reality, `buildFilters` in `utils.js` explicitly supports repeated query parameters as arrays:

```js
if (Array.isArray(values)) {
  if (!isRepeatedQueryParameterValidLength(values)) { ... }
  for (const val of values) {
    filters.push(buildComparatorFilter(key, val));
  }
}
``` [3](#0-2) 

The only guard is `isRepeatedQueryParameterValidLength`, which allows up to `config.query.maxRepeatedQueryParameters` values (default **100**):

```js
const isRepeatedQueryParameterValidLength = (values) =>
  values.length <= config.query.maxRepeatedQueryParameters;
``` [4](#0-3) 

The `qs` parser in `requestHandler.js` is also configured with `arrayLimit: config.query.maxRepeatedQueryParameters`, confirming 100 values are accepted at the HTTP layer: [5](#0-4) 

The default value of 100 is documented: [6](#0-5) 

Both public handlers (`getContractResults` and `getContractResultsById`) call `extractContractResultsByIdQuery` without any additional rate-limiting on the `from` parameter: [7](#0-6) [8](#0-7) 

### Impact Explanation
Each request with 100 unique EVM address `from` values causes 100 sequential DB queries against the `entity` table before the main contract results query runs. The DB connection pool has a default `maxConnections` of 10. A small number of concurrent attackers (e.g., 10 concurrent requests × 100 DB queries each = 1,000 in-flight sequential queries) can saturate the pool, causing legitimate requests to queue or time out (default `statementTimeout`: 20,000 ms). This constitutes a low-cost, unauthenticated denial-of-service against the database layer. [9](#0-8) 

### Likelihood Explanation
The attack requires no credentials, no account, and no special knowledge beyond the public API documentation. The `from` parameter is documented and tested with EVM addresses. The attacker only needs to craft a URL with 100 `from=<unique_40_hex_char_address>` query parameters. This is trivially scriptable and repeatable at high frequency.

### Recommendation
1. **Deduplicate and batch**: Before the loop, collect all EVM-address `from` values, deduplicate them, and resolve them in a single batched DB query (e.g., `WHERE evm_address = ANY($1)`).
2. **Limit EVM-address `from` count**: Enforce a tighter per-parameter sub-limit specifically for `from` values that require DB resolution (e.g., max 5), separate from the global `maxRepeatedQueryParameters`.
3. **Add in-process caching**: Cache EVM-address → encoded-id resolutions in an LRU cache (the configuration already defines `cache.entityId` settings but they are not wired into `EntityService.getEncodedId`).

### Proof of Concept

```bash
# Generate 100 unique fake EVM addresses and send in one request
python3 -c "
import os, urllib.parse
addrs = ['from=0x' + os.urandom(20).hex() for _ in range(100)]
qs = '&'.join(addrs)
print(f'GET /api/v1/contracts/results?{qs}')
" | xargs -I{} curl -s -o /dev/null -w "%{time_total}\n" \
  "http://<mirror-node-host>:5551/api/v1/contracts/results?$(python3 -c "
import os
print('&'.join(['from=0x'+os.urandom(20).hex() for _ in range(100)]))")"
```

Repeat concurrently (e.g., 10 parallel processes). Observe DB connection pool exhaustion and elevated response times or 503 errors for legitimate concurrent requests.

### Citations

**File:** rest/controllers/contractController.js (L439-454)
```javascript
    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.FROM:
          // Evm addresses are not parsed by utils.buildAndValidateFilters, so they are converted to encoded ids here.
          if (EntityId.isValidEvmAddress(filter.value)) {
            filter.value = await EntityService.getEncodedId(filter.value);
          }
          this.updateConditionsAndParamsWithInValues(
            filter,
            contractResultFromInValues,
            params,
            conditions,
            contractResultSenderFullName,
            conditions.length + 1
          );
          break;
```

**File:** rest/controllers/contractController.js (L856-871)
```javascript
  getContractResultsById = async (req, res) => {
    const {contractId: contractIdParam, filters} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractResultsParameters
    );

    const contractId = await ContractService.computeContractIdFromString(contractIdParam);

    const response = {
      results: [],
      links: {
        next: null,
      },
    };
    res.locals[responseDataLabel] = response;
    const {conditions, params, order, limit, skip} = await this.extractContractResultsByIdQuery(filters, contractId);
```

**File:** rest/controllers/contractController.js (L1050-1067)
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
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/utils.js (L488-488)
```javascript
const isRepeatedQueryParameterValidLength = (values) => values.length <= config.query.maxRepeatedQueryParameters;
```

**File:** rest/utils.js (L1240-1253)
```javascript
    if (Array.isArray(values)) {
      if (!isRepeatedQueryParameterValidLength(values)) {
        badParams.push({
          code: InvalidArgumentError.PARAM_COUNT_EXCEEDS_MAX_CODE,
          key,
          count: values.length,
          max: config.query.maxRepeatedQueryParameters,
        });
        continue;
      }

      for (const val of values) {
        filters.push(buildComparatorFilter(key, val));
      }
```

**File:** rest/middleware/requestHandler.js (L15-20)
```javascript
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};
```

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** docs/configuration.md (L582-582)
```markdown
| `hiero.mirror.rest.query.maxRepeatedQueryParameters`                     | 100                     | The maximum number of times any query parameter can be repeated in the uri                                                                                                                    |
```
