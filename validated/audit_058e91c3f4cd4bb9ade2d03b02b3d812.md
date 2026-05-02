Based on my investigation of the actual code, I can verify the key claims against the real implementation.

**Confirmed code mechanics:**

- `getContractResultsById` (line 856–892) calls `extractContractIdAndFiltersFromValidatedRequest(req, acceptedContractResultsParameters)` with no auth check. [1](#0-0) 

- `extractContractIdAndFiltersFromValidatedRequest` (lines 373–382) calls `utils.buildAndValidateFilters` with `contractResultsFilterValidityChecks` — no privilege gate. [2](#0-1) 

- `extractContractResultsByIdQuery` initializes `internal = false`, then the switch-case at lines 478–480 sets `internal = filter.value` when `filterKeys.INTERNAL` is encountered. [3](#0-2) 

- The nonce guard is conditionally omitted at lines 531–533: `if (!internal) { conditions.push(...TRANSACTION_NONCE = 0...); }` [4](#0-3) 

All described code mechanics are confirmed. The `INTERNAL` switch-case being present in `extractContractResultsByIdQuery` is consistent with `filterKeys.INTERNAL` being in `acceptedContractResultsParameters` (if it were not, `buildAndValidateFilters` would strip it before the switch is reached). No authentication or role check appears anywhere in the call chain.

---

Audit Report

## Title
Unprivileged `internal=true` Parameter Bypasses `transaction_nonce = 0` Filter in `getContractResultsById`

## Summary
The `/contracts/:contractId/results` endpoint accepts the `internal` query parameter from any unauthenticated HTTP caller. When `internal=true` is supplied, the SQL condition `cr.transaction_nonce = 0` is omitted from the query, exposing internal (child) contract transactions that are intentionally hidden from the default public API response.

## Finding Description
In `rest/controllers/contractController.js`, `getContractResultsById` (line 856) calls `extractContractIdAndFiltersFromValidatedRequest(req, acceptedContractResultsParameters)` with no authentication or role check preceding it. [1](#0-0) 

`extractContractIdAndFiltersFromValidatedRequest` (line 373) passes the raw query parameters through `utils.buildAndValidateFilters` using `contractResultsFilterValidityChecks`, which applies no privilege restriction on the `INTERNAL` key. [2](#0-1) 

Inside `extractContractResultsByIdQuery`, the `filterKeys.INTERNAL` case (lines 478–480) sets the local `internal` flag directly from the filter value. [5](#0-4) 

At lines 531–533, the nonce guard is conditionally dropped:
```js
if (!internal) {
  conditions.push(`${ContractResult.getFullName(ContractResult.TRANSACTION_NONCE)} = 0`);
}
``` [4](#0-3) 

When `internal=true` is supplied by any caller, this condition is never added, and the query returns all contract results regardless of `transaction_nonce`.

## Impact Explanation
Internal contract transactions (child calls with `transaction_nonce > 0`) are intentionally excluded from the default public API response. Bypassing the nonce filter exposes intermediate call results, internal state transitions, error messages, gas usage details, and created contract IDs for internal calls — data that the API design explicitly hides from public consumers. This constitutes unauthorized information disclosure of internal EVM execution details for any contract.

## Likelihood Explanation
Exploitation requires zero privileges — only the ability to send an HTTP GET request to the public mirror node REST API. The parameter name `internal` is self-documenting. Any developer reading the source code or experimenting with query parameters can discover and exploit this trivially. It is fully repeatable and requires no special tooling.

## Recommendation
1. **Remove `filterKeys.INTERNAL` from `acceptedContractResultsParameters`** so that `buildAndValidateFilters` strips the parameter before it reaches `extractContractResultsByIdQuery` for the public endpoint.
2. If internal results must be accessible to trusted callers (e.g., internal services), gate the `internal` parameter behind an explicit authentication/authorization check (e.g., a verified internal request header or a role claim) before honoring it.
3. Add a regression test asserting that `?internal=true` from an unauthenticated caller does not alter the SQL conditions produced by `extractContractResultsByIdQuery`.

## Proof of Concept
```
GET /api/v1/contracts/0.0.1234/results?internal=true
```
No authentication header required. The resulting SQL query omits `cr.transaction_nonce = 0`, returning all internal child contract results for contract `0.0.1234` that would otherwise be hidden from the public API.

### Citations

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

**File:** rest/controllers/contractController.js (L425-480)
```javascript
    let internal = false;

    const contractResultSenderFullName = ContractResult.getFullName(ContractResult.SENDER_ID);
    const contractResultFromInValues = [];

    const contractResultTimestampFullName = ContractResult.getFullName(ContractResult.CONSENSUS_TIMESTAMP);
    const contractResultTimestampInValues = [];

    const transactionIndexFullName = ContractResult.getFullName(ContractResult.TRANSACTION_INDEX);
    const transactionIndexInValues = [];

    let blockFilter;
    const timestampFilters = [];

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
        case filterKeys.LIMIT:
          limit = filter.value;
          break;
        case filterKeys.ORDER:
          order = filter.value;
          break;
        case filterKeys.TIMESTAMP:
          timestampFilters.push(filter);
          break;
        case filterKeys.BLOCK_NUMBER:
        case filterKeys.BLOCK_HASH:
          blockFilter = filter;
          break;
        case filterKeys.TRANSACTION_INDEX:
          this.updateConditionsAndParamsWithInValues(
            filter,
            transactionIndexInValues,
            params,
            conditions,
            transactionIndexFullName,
            conditions.length + 1
          );
          break;
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

**File:** rest/controllers/contractController.js (L856-860)
```javascript
  getContractResultsById = async (req, res) => {
    const {contractId: contractIdParam, filters} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractResultsParameters
    );
```
