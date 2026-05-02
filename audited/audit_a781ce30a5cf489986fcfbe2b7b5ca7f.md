### Title
Contract Existence Enumeration via Asymmetric Error Response in `getContractResultsById`

### Summary
When `getContractResultsById` receives a CREATE2-style EVM address (opaque 20-byte hex) as `:contractId`, `computeContractIdFromString` performs a live database lookup and throws `NotFoundError` if the address is absent. This propagates as an HTTP 404 with a descriptive message. In contrast, when the contract exists but has no results, the function returns HTTP 200 with an empty `results` array. An unprivileged attacker can exploit this response difference to enumerate which EVM addresses correspond to deployed contracts in the database.

### Finding Description

**Code path:**

`rest/controllers/contractController.js`, `getContractResultsById`, line 862:
```js
const contractId = await ContractService.computeContractIdFromString(contractIdParam);
``` [1](#0-0) 

`computeContractIdFromString` in `rest/service/contractService.js` (lines 468–476) branches on whether the input is a CREATE2 EVM address: [2](#0-1) 

If `create2_evm_address` is present, it calls `getContractIdByEvmAddress`, which issues a DB query and **throws `NotFoundError`** when zero rows are returned: [3](#0-2) 

The error middleware in `rest/middleware/httpErrorHandler.js` maps `NotFoundError` → HTTP 404 and returns the error message body to the caller (client errors pass `shouldReturnMessage`): [4](#0-3) [5](#0-4) 

**Root cause:** `getContractResultsById` has no try/catch around `computeContractIdFromString`. For a non-existent EVM address the exception propagates directly to the error middleware (HTTP 404 + message). For an existing contract with no results, the code reaches line 877 and returns HTTP 200 `{"results":[],"links":{"next":null}}`. These two observable states are distinct.

**Why the existing check is insufficient:** The `if (rows.length === 0) { return; }` guard at line 877 only applies after a successful ID resolution. It never executes when `computeContractIdFromString` throws. There is no normalization layer that converts `NotFoundError` into an empty-results response for this endpoint. [6](#0-5) 

**Contrast with shard.realm.num IDs:** When a numeric entity ID (e.g., `0.0.99999`) is supplied, `computeContractIdFromString` skips the DB lookup entirely and returns the encoded ID unconditionally (line 475). A non-existent numeric contract therefore returns HTTP 200 with empty results — indistinguishable from an existing contract with no results. The enumeration vector is exclusive to CREATE2 EVM addresses. [7](#0-6) 

### Impact Explanation
An attacker can determine, with certainty and at zero cost, whether any arbitrary 20-byte EVM address is registered as a contract in the mirror node database. This leaks the full set of deployed CREATE2 contract addresses, which may be considered sensitive deployment intelligence (e.g., revealing internal infrastructure, undisclosed protocol contracts, or pre-deployment staging addresses). The information asymmetry is binary and unambiguous: 404 = does not exist, 200 = exists.

### Likelihood Explanation
No authentication or rate-limiting is required. The endpoint is public. The attacker only needs to supply a syntactically valid 40-hex-character address (with or without `0x` prefix). The check in `computeContractIdPartsFromContractIdValue` accepts bare hex strings as `create2_evm_address` inputs: [8](#0-7) 

Automated scanning of the full 2^160 address space is impractical, but targeted probing of known or suspected addresses (e.g., deterministic CREATE2 addresses computed off-chain) is entirely feasible and repeatable.

### Recommendation
In `getContractResultsById`, catch `NotFoundError` thrown by `computeContractIdFromString` and return the same empty-results response that is returned when the contract exists but has no results:

```js
let contractId;
try {
  contractId = await ContractService.computeContractIdFromString(contractIdParam);
} catch (e) {
  if (e instanceof NotFoundError) {
    // Treat non-existent EVM address identically to existing contract with no results
    return;
  }
  throw e;
}
```

This normalizes both cases to HTTP 200 `{"results":[],"links":{"next":null}}`, eliminating the observable difference. The same fix should be applied to `getContractLogsById` and `getContractStateById`, which call `computeContractIdFromString` under the same pattern. [9](#0-8) [10](#0-9) 

### Proof of Concept

**Precondition:** Mirror node REST API is running. EVM address `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef` is not registered as a contract in the database.

**Step 1 — Probe a non-existent EVM address:**
```
GET /api/v1/contracts/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/results
```
**Response:** HTTP 404
```json
{
  "_status": {
    "messages": [{"message": "No contract with the given evm address 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef has been found."}]
  }
}
```

**Step 2 — Probe an existing contract with no results (e.g., `0x<known_create2_address>`):**
```
GET /api/v1/contracts/0x<known_create2_address>/results
```
**Response:** HTTP 200
```json
{"results": [], "links": {"next": null}}
```

**Step 3 — Conclusion:** The HTTP status code alone (404 vs 200) unambiguously reveals contract existence. An attacker can automate this probe across any set of candidate EVM addresses with no privileges required.

### Citations

**File:** rest/controllers/contractController.js (L779-800)
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
```

**File:** rest/controllers/contractController.js (L856-879)
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
    if (skip) {
      return;
    }

    const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
    if (rows.length === 0) {
      return;
    }
```

**File:** rest/controllers/contractController.js (L964-972)
```javascript
  getContractStateById = async (req, res) => {
    const {contractId: contractIdParam, filters} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractStateParameters
    );
    const contractId = await ContractService.computeContractIdFromString(contractIdParam);
    const {conditions, order, limit, timestamp} = await this.extractContractStateByIdQuery(filters, contractId);
    const rows = await ContractService.getContractStateByIdAndFilters(conditions, order, limit, timestamp);
    const state = rows.map((row) => new ContractStateViewModel(row));
```

**File:** rest/service/contractService.js (L452-459)
```javascript
  async getContractIdByEvmAddress(evmAddressFilter) {
    const create2EvmAddress = evmAddressFilter.create2_evm_address;
    const rows = await super.getRows(ContractService.contractIdByEvmAddressQuery, [
      Buffer.from(create2EvmAddress, 'hex'),
    ]);
    if (rows.length === 0) {
      throw new NotFoundError(`No contract with the given evm address 0x${create2EvmAddress} has been found.`);
    }
```

**File:** rest/service/contractService.js (L468-476)
```javascript
  async computeContractIdFromString(contractIdValue) {
    const contractIdParts = EntityId.computeContractIdPartsFromContractIdValue(contractIdValue);

    if (contractIdParts.hasOwnProperty('create2_evm_address')) {
      return this.getContractIdByEvmAddress(contractIdParts);
    }

    return EntityId.parseString(contractIdValue, {paramName: filterKeys.CONTRACTID}).getEncodedId();
  }
```

**File:** rest/middleware/httpErrorHandler.js (L17-18)
```javascript
  if (err instanceof NotFoundError) {
    statusCode = httpStatusCodes.NOT_FOUND;
```

**File:** rest/middleware/httpErrorHandler.js (L31-42)
```javascript
  if (shouldReturnMessage(statusCode)) {
    errorMessage = err.message;
    logger.warn(
      `${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode} ${err.constructor.name} ${errorMessage}`
    );
  } else {
    errorMessage = statusCode.message;
    const detailedMessage = shouldPrintStacktrace(err) ? err : err.message;
    logger.error(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${statusCode}`, detailedMessage);
  }

  res.status(statusCode.code).json(errorMessageFormat(errorMessage));
```

**File:** rest/entityId.js (L284-299)
```javascript
const computeContractIdPartsFromContractIdValue = (contractId) => {
  const [shard, realm, evmAddressOrNum] = piecesFromString(contractId);

  const contractIdParts = {
    shard: shard,
    realm: realm,
  };

  if (isEvmAddressAlias(evmAddressOrNum)) {
    contractIdParts.create2_evm_address = evmAddressOrNum;
  } else {
    contractIdParts.num = evmAddressOrNum;
  }

  return contractIdParts;
};
```
