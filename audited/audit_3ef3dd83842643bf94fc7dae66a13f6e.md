### Title
Unauthenticated Access to Internal Contract Call Results via `internal=true` Query Parameter

### Summary
The `internal` query parameter on the `/api/v1/contracts/results` and `/api/v1/contracts/{id}/results` endpoints is publicly accessible with no authentication or authorization check. By default, the API filters out internal sub-calls by enforcing `transaction_nonce = 0` in the SQL query. Any unauthenticated user can bypass this filter by supplying `internal=true`, causing the mirror node to return all internal contract execution records (those with `transaction_nonce > 0`) that are intentionally excluded from the default response.

### Finding Description
**Root cause — no access control on the `internal` filter:**

`filterKeys.INTERNAL = 'internal'` is defined in `rest/constants.js` line 38 and is included in the publicly accepted parameter set:

```js
// rest/controllers/contractController.js lines 1336-1346
const acceptedContractResultsParameters = new Set([
  filterKeys.FROM,
  filterKeys.BLOCK_HASH,
  filterKeys.BLOCK_NUMBER,
  filterKeys.HBAR,
  filterKeys.INTERNAL,   // ← publicly accepted, no privilege check
  ...
]);
```

Inside `extractContractResultsByIdQuery`, the `internal` variable defaults to `false` and is set directly from the user-supplied filter value:

```js
// lines 425, 478-480
let internal = false;
...
case filterKeys.INTERNAL:
  internal = filter.value;   // ← user-controlled
  break;
```

The only guard protecting internal records is:

```js
// lines 531-533
if (!internal) {
  conditions.push(`${ContractResult.getFullName(ContractResult.TRANSACTION_NONCE)} = 0`);
}
```

When `internal=true` is supplied, the `transaction_nonce = 0` condition is never appended, so the SQL query returns all rows including those with `transaction_nonce > 0` (internal sub-calls).

**Why existing checks are insufficient:**

The `authHandler` middleware (`rest/middleware/authHandler.js` lines 15-36) is purely optional — it only sets a custom rate-limit for known users and explicitly returns without blocking when no credentials are provided:

```js
if (!credentials) {
  return;  // ← unauthenticated requests proceed normally
}
```

The `filterValidityChecks` in `rest/utils.js` lines 327-329 only validates that the value is a valid boolean — it performs no privilege check:

```js
case constants.filterKeys.INTERNAL:
  ret = isValidBooleanOpAndValue(op, val);
  break;
```

The routes in `rest/routes/contractRoute.js` lines 14 and 19 register both endpoints with no authentication middleware:

```js
router.getExt('/:contractId/results', ContractController.getContractResultsById);
router.getExt('/results', ContractController.getContractResults);
```

### Impact Explanation
An unauthenticated attacker can retrieve internal contract sub-call records that are intentionally hidden from the default API. These records include `function_parameters`, `call_result`/`function_result`, `sender_id`, `bloom`, `created_contract_ids`, `error_message`, and gas details for every internal contract-to-contract call. This exposes the internal execution logic of smart contracts, potentially leaking sensitive data passed between contracts, internal state transitions, and contract addresses that were not meant to be publicly enumerated. The severity is **Medium-High**: the data is read-only but the disclosure is unintended and bypasses the designed access boundary.

### Likelihood Explanation
The exploit requires zero privileges, zero authentication, and zero special tooling — a single HTTP GET request with `?internal=true` appended. It is trivially repeatable by any external user who reads the OpenAPI spec (which documents `internalQueryParam` at `rest/api/v1/openapi.yml` lines 650, 570) or simply experiments with the query string. The attack is fully passive and leaves no distinguishable trace beyond normal API access logs.

### Recommendation
1. **Restrict the parameter to authenticated/privileged users**: In `extractContractResultsByIdQuery`, check whether the caller has an elevated role/credential before honoring `internal=true`. Reject or silently ignore the parameter for unauthenticated requests.
2. **Alternatively, remove the parameter from the public API** if internal results are never intended for external consumers, and expose it only via an internal/admin endpoint protected by authentication middleware.
3. **Add an integration test** asserting that unauthenticated requests to `/api/v1/contracts/results?internal=true` return only `transaction_nonce = 0` records.

### Proof of Concept
```
# No credentials required. Works against any deployed mirror node REST API.

curl -s "https://<mirror-node-host>/api/v1/contracts/results?internal=true"

# Or for a specific contract:
curl -s "https://<mirror-node-host>/api/v1/contracts/0.0.5001/results?internal=true"

# Expected (vulnerable) result: HTTP 200 with results containing entries
# where transaction_nonce > 0 (internal sub-calls), which are absent from
# the default response without the internal=true parameter.

# Confirm the difference:
curl -s "https://<mirror-node-host>/api/v1/contracts/0.0.5001/results"
# → returns only top-level calls (transaction_nonce = 0)

curl -s "https://<mirror-node-host>/api/v1/contracts/0.0.5001/results?internal=true"
# → returns top-level AND internal sub-calls (transaction_nonce > 0),
#   including function_parameters, call_result, sender_id, etc.
```