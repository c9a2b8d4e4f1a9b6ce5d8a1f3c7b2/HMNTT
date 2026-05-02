### Title
`NotFoundError` Propagation in `extractContractResultsByIdQuery` Causes HTTP 404 Instead of Empty Results for Unresolvable `from` EVM Address

### Summary
In `extractContractResultsByIdQuery()`, when a `from` query parameter contains a syntactically valid EVM address that has no matching entity in the database, `EntityService.getEncodedId()` is called with `requireResult = true` (the default). This causes a `NotFoundError` to be thrown, which propagates uncaught through the entire call stack and is converted by the Express error handler into an HTTP 404 response — instead of the correct behavior of returning an empty result set. Any unauthenticated user can trigger this on both `/api/v1/contracts/results` and `/api/v1/contracts/:contractId/results`.

### Finding Description

**Exact code path:**

In `contractController.js`, `extractContractResultsByIdQuery()` handles the `FROM` filter:

```javascript
case filterKeys.FROM:
  if (EntityId.isValidEvmAddress(filter.value)) {
    filter.value = await EntityService.getEncodedId(filter.value);  // requireResult defaults to true
  }
``` [1](#0-0) 

`EntityService.getEncodedId()` with `requireResult = true` (the default) calls `getEntityIdFromEvmAddress()`:

```javascript
async getEntityIdFromEvmAddress(entityId, requireResult = true) {
  const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [...]);
  if (rows.length === 0) {
    if (requireResult) {
      throw new NotFoundError();   // <-- thrown when address not in DB
    }
    return null;
  }
  ...
}
``` [2](#0-1) 

The `catch` block in `getEncodedId()` only re-maps `InvalidArgumentError`; `NotFoundError` is rethrown as-is:

```javascript
} catch (ex) {
  if (ex instanceof InvalidArgumentError) {
    throw InvalidArgumentError.forParams(paramName);
  }
  throw ex;   // NotFoundError passes through here
}
``` [3](#0-2) 

Neither `extractContractResultsByIdQuery` nor its callers (`getContractResults`, `getContractResultsById`) have any try-catch: [4](#0-3) [5](#0-4) 

The Express error handler maps `NotFoundError` → HTTP 404:

```javascript
if (err instanceof NotFoundError) {
  statusCode = httpStatusCodes.NOT_FOUND;
}
``` [6](#0-5) 

**Root cause:** The call `EntityService.getEncodedId(filter.value)` omits the `requireResult` argument, so it defaults to `true`. A non-existent but syntactically valid EVM address causes `NotFoundError` to be thrown and propagate uncaught, aborting the request with a 404 error body instead of returning `{results: [], links: {next: null}}`.

### Impact Explanation

Any request to `/api/v1/contracts/results?from=<valid_format_nonexistent_evm_address>` or `/api/v1/contracts/:contractId/results?from=<...>` returns:
```json
{"_status": {"messages": [{"message": "Not found"}]}}
```
with HTTP 404, instead of an empty result list. This constitutes:
1. **Denial of visibility**: the caller cannot distinguish "no results match" from "address not found" — the API surface is broken for this input class.
2. **Information disclosure**: the 404 response confirms the EVM address has no entity record in the mirror node database, enabling address enumeration with no authentication.

### Likelihood Explanation

Trivially exploitable by any unauthenticated user. No special knowledge, credentials, or rate-limit bypass is required. The attacker only needs to supply a syntactically valid 20-byte hex EVM address (e.g., `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`) that is not registered in the network. This is the common case for most EVM addresses. The attack is fully repeatable and stateless.

### Recommendation

Pass `requireResult = false` to `getEncodedId()` and handle the `null` return by either skipping the filter (returning all results) or short-circuiting with an empty result set:

```javascript
case filterKeys.FROM:
  if (EntityId.isValidEvmAddress(filter.value)) {
    const encodedId = await EntityService.getEncodedId(filter.value, false);
    if (encodedId === null) {
      return {conditions: [], params: [], order, limit, skip: true};
    }
    filter.value = encodedId;
  }
  ...
```

This matches the existing `skip: true` pattern already used for unresolvable block filters. [7](#0-6) 

### Proof of Concept

**Precondition:** Mirror node REST API is running. The EVM address `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef` does not exist in the entity table (true for virtually any random address).

**Request:**
```
GET /api/v1/contracts/results?from=0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

**Expected (correct) response:** HTTP 200
```json
{"results": [], "links": {"next": null}}
```

**Actual response:** HTTP 404
```json
{"_status": {"messages": [{"message": "Not found"}]}}
```

**Reproducible steps:**
1. Pick any 40-hex-character EVM address not registered on the network.
2. Send `GET /api/v1/contracts/results?from=0x<address>` with no authentication.
3. Observe HTTP 404 instead of an empty result list.
4. Repeat with `GET /api/v1/contracts/<any_valid_contract_id>/results?from=0x<address>` — same result.

### Citations

**File:** rest/controllers/contractController.js (L441-445)
```javascript
        case filterKeys.FROM:
          // Evm addresses are not parsed by utils.buildAndValidateFilters, so they are converted to encoded ids here.
          if (EntityId.isValidEvmAddress(filter.value)) {
            filter.value = await EntityService.getEncodedId(filter.value);
          }
```

**File:** rest/controllers/contractController.js (L498-501)
```javascript
        );
      } else {
        return {skip: true};
      }
```

**File:** rest/controllers/contractController.js (L856-875)
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

```

**File:** rest/controllers/contractController.js (L1050-1070)
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
```

**File:** rest/service/entityService.js (L90-104)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }

      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching evm address ${entityId}`);
      throw new Error(EntityService.multipleEvmAddressMatch);
    }

    return rows[0].id;
  }
```

**File:** rest/service/entityService.js (L128-134)
```javascript
    } catch (ex) {
      if (ex instanceof InvalidArgumentError) {
        throw InvalidArgumentError.forParams(paramName);
      }
      // rethrow
      throw ex;
    }
```

**File:** rest/middleware/httpErrorHandler.js (L17-18)
```javascript
  if (err instanceof NotFoundError) {
    statusCode = httpStatusCodes.NOT_FOUND;
```
