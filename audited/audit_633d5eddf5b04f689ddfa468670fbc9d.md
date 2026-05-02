### Title
EVM Address Existence Oracle via `from=` Filter in `getContractResultsById()`

### Summary
An unauthenticated attacker can supply any syntactically valid EVM address as the `from=` query parameter to `GET /api/v1/contracts/:contractId/results`. The server performs a live database lookup for the address before executing the main query, and the HTTP response code (404 vs 200) directly reveals whether that EVM address exists in the `entity` table — creating a reliable, noiseless enumeration oracle.

### Finding Description

**Exact code path:**

`getContractResultsById` (contractController.js:856) calls `extractContractResultsByIdQuery` (line 871), which iterates over filters. For `filterKeys.FROM`:

```js
// contractController.js lines 441-444
case filterKeys.FROM:
  if (EntityId.isValidEvmAddress(filter.value)) {
    filter.value = await EntityService.getEncodedId(filter.value);  // ← DB lookup, requireResult=true
  }
``` [1](#0-0) 

`EntityService.getEncodedId` is called with the default `requireResult = true`:

```js
// entityService.js lines 118-124
async getEncodedId(entityIdString, requireResult = true, ...) {
  if (EntityId.isValidEntityId(entityIdString)) {
    const entityId = EntityId.parseString(entityIdString, {paramName});
    return entityId.evmAddress === null
      ? entityId.getEncodedId()
      : await this.getEntityIdFromEvmAddress(entityId, requireResult);  // ← DB query
  }
``` [2](#0-1) 

`getEntityIdFromEvmAddress` throws `NotFoundError` when the address is absent:

```js
// entityService.js lines 92-94
if (rows.length === 0) {
  if (requireResult) {
    throw new NotFoundError();   // ← propagates as HTTP 404
  }
``` [3](#0-2) 

The error middleware maps `NotFoundError` → HTTP 404:

```js
// httpErrorHandler.js lines 17-18
if (err instanceof NotFoundError) {
  statusCode = httpStatusCodes.NOT_FOUND;
``` [4](#0-3) 

**Root cause:** `getEncodedId` is called with `requireResult = true` (the default) during filter pre-processing, before the main contract-results query runs. This means the error path (address absent → 404) and the success path (address present → 200, even with zero results) are observably different at the HTTP layer.

**Why existing checks are insufficient:** `EntityId.isValidEvmAddress()` only validates the 20-byte hex format; it does not prevent the subsequent DB lookup. There is no normalization that converts a "not found during filter resolution" into an empty-result 200 response.

### Impact Explanation

An attacker can enumerate which EVM addresses are registered in the Hedera entity table with 100% reliability using only HTTP response codes — no timing measurement required. This leaks the mapping between EVM addresses and Hedera entity existence, enabling targeted reconnaissance (e.g., confirming whether a specific contract or account address is live on the network before mounting further attacks). Severity: **Medium** (information disclosure, no authentication bypass or fund loss directly, but enables precise enumeration of on-chain entities). [5](#0-4) 

### Likelihood Explanation

The endpoint is public and unauthenticated. The oracle is binary and noiseless (HTTP 404 vs 200), requiring no statistical analysis. Any attacker with network access can script a loop over candidate EVM addresses. No special privileges, tokens, or prior knowledge beyond a valid contract ID path parameter are needed. [1](#0-0) 

### Recommendation

Pass `requireResult = false` when resolving the `from=` filter value, and treat a `null` return (address not found) as a no-match condition that returns an empty result set (HTTP 200) rather than propagating a 404:

```js
case filterKeys.FROM:
  if (EntityId.isValidEvmAddress(filter.value)) {
    const encodedId = await EntityService.getEncodedId(filter.value, false); // requireResult=false
    if (encodedId === null) {
      return {skip: true};  // address unknown → return empty results, not 404
    }
    filter.value = encodedId;
  }
```

This makes the response indistinguishable whether the address is absent or simply has no matching contract results. [6](#0-5) 

### Proof of Concept

**Preconditions:** Public access to the mirror node REST API; any valid contract ID (e.g., `0.0.1234`).

**Step 1 — Confirm oracle with a known-absent address:**
```
GET /api/v1/contracts/0.0.1234/results?from=0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
→ HTTP 404  {"_status":{"messages":[{"message":"Not found"}]}}
```

**Step 2 — Confirm oracle with a known-present address (e.g., obtained from a prior transaction):**
```
GET /api/v1/contracts/0.0.1234/results?from=0x<known_registered_evm_address>
→ HTTP 200  {"results":[], "links":{"next":null}}
```

**Step 3 — Enumerate:**
```python
for addr in candidate_addresses:
    r = requests.get(f"/api/v1/contracts/0.0.1234/results?from={addr}")
    if r.status_code == 200:
        print(f"EXISTS: {addr}")   # address is in entity table
    elif r.status_code == 404:
        print(f"ABSENT: {addr}")
```

The response code alone, with zero ambiguity, reveals EVM address existence in the entity table. [7](#0-6)

### Citations

**File:** rest/controllers/contractController.js (L441-444)
```javascript
        case filterKeys.FROM:
          // Evm addresses are not parsed by utils.buildAndValidateFilters, so they are converted to encoded ids here.
          if (EntityId.isValidEvmAddress(filter.value)) {
            filter.value = await EntityService.getEncodedId(filter.value);
```

**File:** rest/controllers/contractController.js (L856-892)
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

    response.results = rows.map((row) => new ContractResultViewModel(row));
    const lastRow = last(response.results);
    const lastContractResultTimestamp = lastRow.timestamp;
    response.links.next = utils.getPaginationLink(
      req,
      response.results.length !== limit,
      {
        [filterKeys.TIMESTAMP]: lastContractResultTimestamp,
      },
      order
    );
  };
```

**File:** rest/service/entityService.js (L92-95)
```javascript
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }
```

**File:** rest/service/entityService.js (L118-137)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
    } catch (ex) {
      if (ex instanceof InvalidArgumentError) {
        throw InvalidArgumentError.forParams(paramName);
      }
      // rethrow
      throw ex;
    }

    throw InvalidArgumentError.forParams(paramName);
  }
```

**File:** rest/middleware/httpErrorHandler.js (L14-25)
```javascript
const handleError = async (err, req, res, next) => {
  var statusCode = defaultStatusCode;

  if (err instanceof NotFoundError) {
    statusCode = httpStatusCodes.NOT_FOUND;
  } else if (err instanceof InvalidArgumentError || err instanceof RangeError) {
    statusCode = httpStatusCodes.BAD_REQUEST;
  } else if (err instanceof DbError) {
    statusCode = httpStatusCodes.SERVICE_UNAVAILABLE;
  } else if (err instanceof HttpError) {
    statusCode = new StatusCode(err.statusCode, err.msg);
  }
```
