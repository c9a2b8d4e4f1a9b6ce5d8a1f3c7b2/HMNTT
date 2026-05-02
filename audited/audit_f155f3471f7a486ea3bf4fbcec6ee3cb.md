### Title
Unprivileged `internal=true` Parameter Bypasses `transaction_nonce = 0` Filter in `getContractResultsById`

### Summary
The `getContractResultsById` handler accepts the `internal` query parameter from any unauthenticated caller via `extractContractIdAndFiltersFromValidatedRequest`. When `internal=true` is supplied, the `extractContractResultsByIdQuery` method omits the `cr.transaction_nonce = 0` SQL condition, exposing internal (child) contract transactions that are normally hidden from the public API. No privilege check gates this parameter.

### Finding Description
**Code path:**

`rest/controllers/contractController.js`, `getContractResultsById` (line 856–892): [1](#0-0) 

It calls `extractContractIdAndFiltersFromValidatedRequest(req, acceptedContractResultsParameters)` (line 857–860), which in turn calls `utils.buildAndValidateFilters(req.query, acceptedParameters, contractResultsFilterValidityChecks)` (line 376): [2](#0-1) 

The `contractResultsFilterValidityChecks` validator adds no privilege restriction — it only adds a special operator check for `BLOCK_NUMBER` and otherwise delegates to the generic `utils.filterValidityChecks`: [3](#0-2) 

Inside `extractContractResultsByIdQuery`, the `INTERNAL` filter key is handled in the switch and sets the local `internal` flag: [4](#0-3) 

At the end of query construction, the nonce filter is conditionally omitted: [5](#0-4) 

**Root cause:** `filterKeys.INTERNAL` is present in `acceptedContractResultsParameters` (evidenced by the switch-case handling it — if it were not accepted, `buildAndValidateFilters` would strip it before it ever reached the switch). No authentication or role check is applied before the `internal` flag is honored. Any caller who passes `?internal=true` causes the `transaction_nonce = 0` guard to be dropped entirely.

**Failed assumption:** The design assumes that only internal/trusted callers will ever set `internal=true`. There is no enforcement of this assumption in the code.

### Impact Explanation
Internal contract transactions (child calls spawned by a smart contract, which have `transaction_nonce > 0`) are intentionally hidden from the public REST API. Bypassing the `transaction_nonce = 0` filter leaks the full set of internal contract results for any contract, including intermediate call results, internal state transitions, error messages, gas usage, and created contract IDs that are not meant to be directly queryable. This constitutes an unauthorized information disclosure of internal EVM execution details.

### Likelihood Explanation
The exploit requires zero privileges — only the ability to send an HTTP GET request to the public mirror node REST API. The parameter name (`internal`) is self-documenting. Any developer or attacker reading the source code or experimenting with query parameters can discover and exploit this trivially. It is fully repeatable and requires no special tooling.

### Recommendation
1. Remove `filterKeys.INTERNAL` from `acceptedContractResultsParameters` so that `buildAndValidateFilters` rejects the parameter before it reaches `extractContractResultsByIdQuery`.
2. If `internal=true` must remain available for internal/trusted callers (e.g., other services), gate it behind a middleware that checks a trusted header or IP allowlist before the filter is parsed.
3. Add an integration test asserting that `GET /contracts/{id}/results?internal=true` from an unprivileged caller returns the same results as without the parameter (i.e., the nonce filter is always applied for public callers).

### Proof of Concept
```
# 1. Identify a contract that has internal transactions (transaction_nonce > 0)
#    e.g., contract 0.0.1234 which was called by another contract

# 2. Normal public request — only returns top-level results (transaction_nonce = 0)
GET /api/v1/contracts/0.0.1234/results
# -> Returns only results where transaction_nonce = 0

# 3. Exploit — pass internal=true to drop the nonce filter
GET /api/v1/contracts/0.0.1234/results?internal=true
# -> Returns ALL contract_result rows for contract 0.0.1234,
#    including those with transaction_nonce > 0 (internal child calls),
#    exposing intermediate execution data not intended for public access.
```

The difference in result sets between step 2 and step 3 confirms the filter bypass. No authentication token or special header is required.

### Citations

**File:** rest/controllers/contractController.js (L273-279)
```javascript
const contractResultsFilterValidityChecks = (param, op, val) => {
  const ret = utils.filterValidityChecks(param, op, val);
  if (ret && param === filterKeys.BLOCK_NUMBER) {
    return op === queryParamOperators.eq;
  }
  return ret;
};
```

**File:** rest/controllers/contractController.js (L373-382)
```javascript
const extractContractIdAndFiltersFromValidatedRequest = (req, acceptedParameters) => {
  // extract filters from query param
  const contractId = getAndValidateContractIdRequestPathParam(req);
  const filters = utils.buildAndValidateFilters(req.query, acceptedParameters, contractResultsFilterValidityChecks);

  return {
    contractId,
    filters,
  };
};
```

**File:** rest/controllers/contractController.js (L478-480)
```javascript
        case filterKeys.INTERNAL:
          internal = filter.value;
          break;
```

**File:** rest/controllers/contractController.js (L531-533)
```javascript
    if (!internal) {
      conditions.push(`${ContractResult.getFullName(ContractResult.TRANSACTION_NONCE)} = 0`);
    }
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
