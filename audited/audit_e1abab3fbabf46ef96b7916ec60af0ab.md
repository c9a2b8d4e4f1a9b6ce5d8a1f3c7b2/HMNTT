### Title
Unprivileged User Can Trigger 206 PARTIAL_CONTENT with Null `callResult`, Silently Consumed by Clients Using `httpStatusCodes.isSuccess`

### Summary
Any unauthenticated external user can query a contract result endpoint for a transaction whose record has not yet been fully ingested by the mirror node. The server responds with HTTP 206 and a body where `callResult` is `null`. Because `httpStatusCodes.isSuccess` in `constants.js` classifies all 2xx codes (including 206) as success, any internal or downstream consumer using that helper will silently accept the incomplete record as a complete one.

### Finding Description

**Trigger locations** — `rest/controllers/contractController.js`:

- `getContractResultsByTimestamp` (lines 1026–1030): [1](#0-0) 
- `getContractResultsByTransactionIdOrHash` (lines 1198–1202): [2](#0-1) 

Both handlers check `isNil(contractResult.callResult)` and, when true, write `res.locals.statusCode = httpStatusCodes.PARTIAL_CONTENT.code` (206) **after** `setContractResultsResponse` has already placed the incomplete `ContractResultDetailsViewModel` (with `callResult: null`) into `res.locals[responseDataLabel]`. [3](#0-2) 

**Failed assumption** — `constants.js` defines:

```js
isSuccess: (code) => code >= 200 && code < 300,
``` [4](#0-3) 

This function is exported and available to every module in the REST layer (monitoring, caching middleware, etc.). Any caller that uses `httpStatusCodes.isSuccess(statusCode)` to gate further processing will treat a 206 identically to a 200, never inspecting whether `callResult` is null.

**Root cause**: The partial-content signal (206) is set on `res.locals.statusCode` only, with no corresponding field in the response body (no `"partial": true` flag, no `"missing_fields"` list). The body is structurally identical to a 200 response except that `callResult` is `null`. Consumers that do not explicitly branch on 206 receive no machine-readable indication that the record is incomplete.

### Impact Explanation

A downstream integration (exchange, wallet, DeFi bridge) that polls `/api/v1/contracts/{id}/results/{timestamp}` or `/api/v1/contracts/results/{txHash}` and checks only for HTTP 2xx will:

1. Accept the response as authoritative.
2. Record `callResult = null` as the canonical execution output.
3. Make downstream decisions (e.g., confirming a smart-contract call succeeded, crediting funds, updating on-chain state) based on incomplete data.

Because `callResult` carries the ABI-encoded return value of the contract call, its absence can cause incorrect ABI decoding, silent zero-value substitution, or a crash that is swallowed by a try/catch, depending on the client library.

Severity: **Medium** — no authentication bypass or data exfiltration, but silent data-integrity failure in financial/protocol-critical consumers.

### Likelihood Explanation

- **No privilege required**: the two affected endpoints are fully public.
- **Repeatable**: any transaction that arrives at the mirror node before its record file is fully parsed will produce a null `callResult`. An attacker can deliberately query the endpoint immediately after submitting a transaction to reliably obtain a 206.
- **Broad surface**: the `httpStatusCodes.isSuccess` helper is exported from `constants.js` and referenced by the response-cache middleware and metrics handler, meaning the incomplete response can also be cached and re-served as "successful" to subsequent callers during the cache TTL window.

### Recommendation

1. **Add a body-level signal**: include a `"partial": true` field (or `"missing_fields": ["call_result"]`) in the 206 response body so clients that do not inspect the HTTP status code still have a machine-readable indicator.
2. **Fix `httpStatusCodes.isSuccess`**: either exclude 206 from the success range, or add a separate `isComplete` predicate that returns `false` for 206, and use it in the caching and metrics middleware.
3. **Document the contract**: the OpenAPI spec for both endpoints should explicitly declare the 206 response code and its semantics so SDK generators produce clients that handle it correctly.
4. **Cache guard**: the response-cache middleware should not cache 206 responses, or should cache them with a very short TTL, to prevent stale partial data from being served to subsequent callers.

### Proof of Concept

```
# 1. Submit a contract call transaction to the Hedera network.
# 2. Immediately (before the mirror node finishes ingesting the record file) query:

GET /api/v1/contracts/results/<txHash>
# or
GET /api/v1/contracts/<contractId>/results/<consensusTimestamp>

# 3. Observe HTTP 206 with body:
{
  "call_result": null,
  "bloom": "...",
  ...
}

# 4. A naive client:
if (response.status >= 200 && response.status < 300) {
  processResult(response.body);   // silently processes null callResult
}

# 5. Confirm with httpStatusCodes.isSuccess:
httpStatusCodes.isSuccess(206)  // → true  (constants.js line 159)
```

### Citations

**File:** rest/controllers/contractController.js (L1026-1030)
```javascript
    if (isNil(contractResults[0].callResult)) {
      // set 206 partial response
      res.locals.statusCode = httpStatusCodes.PARTIAL_CONTENT.code;
      logger.debug(`getContractResultsByTimestamp returning partial content`);
    }
```

**File:** rest/controllers/contractController.js (L1198-1202)
```javascript
    if (isNil(contractResult.callResult)) {
      // set 206 partial response
      res.locals.statusCode = httpStatusCodes.PARTIAL_CONTENT.code;
      logger.debug(`getContractResultsByTransactionId returning partial content`);
    }
```

**File:** rest/controllers/contractController.js (L1293-1312)
```javascript
  setContractResultsResponse = (
    res,
    contractResult,
    recordFile,
    ethTransaction,
    contractLogs,
    contractStateChanges,
    fileData,
    convertToHbar = true
  ) => {
    res.locals[responseDataLabel] = new ContractResultDetailsViewModel(
      contractResult,
      recordFile,
      ethTransaction,
      contractLogs,
      contractStateChanges,
      fileData,
      convertToHbar
    );
  };
```

**File:** rest/constants.js (L159-159)
```javascript
  isSuccess: (code) => code >= 200 && code < 300,
```
