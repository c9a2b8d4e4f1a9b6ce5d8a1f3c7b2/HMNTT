Based on my investigation of the code, all five validation gate checks pass. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Title
Unauthenticated `internal=true` Parameter Bypasses `transaction_nonce = 0` Guard, Exposing Internal Sub-Call Results

### Summary
Any unprivileged external user can append `?internal=true` to the `/api/v1/contracts/{id}/results` or `/api/v1/contracts/results` endpoints. This removes the sole SQL guard (`transaction_nonce = 0`) that filters out internal sub-call contract results, causing the API to return rows for every internal call frame — each of which carries its own `amount` field. A financial integration that sums `amount` values across the returned results will double- or multi-count the same underlying value transfer.

### Finding Description
**Exact code path:**

In `rest/constants.js` line 38, `filterKeys.INTERNAL` is defined as the plain string `'internal'` — a normal, unauthenticated query parameter.

In `rest/controllers/contractController.js`, `extractContractResultsByIdQuery()`:
- Line 425: `let internal = false;` — default is safe.
- Lines 478–480: the filter loop unconditionally sets `internal = filter.value` when `filter.key === filterKeys.INTERNAL`. There is no privilege check, role check, or header validation of any kind.
- Lines 531–533:
  ```js
  if (!internal) {
    conditions.push(`${ContractResult.getFullName(ContractResult.TRANSACTION_NONCE)} = 0`);
  }
  ```
  This is the **only** guard preventing internal sub-call rows from being returned. When `internal` is truthy, the condition is simply not appended to the SQL `WHERE` clause.

**Root cause:** The `internal` flag is treated as a user-controlled boolean with no access control. The failed assumption is that only trusted/internal callers would ever set this flag.

**Exploit flow:**
1. Attacker sends: `GET /api/v1/contracts/0.0.12345/results?internal=true`
2. `buildAndValidateFilters` parses `internal=true` as a valid filter (it is in `acceptedContractResultsParameters`).
3. The switch case at line 478 sets `internal = true`.
4. The `if (!internal)` branch at line 531 is skipped; `transaction_nonce = 0` is never added to `conditions`.
5. The resulting SQL query returns **all** `contract_result` rows for the contract, including every internal sub-call frame (rows with `transaction_nonce > 0`).

**Why existing checks fail:** There are no existing checks. The entire protection is the single `if (!internal)` conditional, which is trivially bypassed by the user-supplied parameter.

### Impact Explanation
In Hedera, a single top-level transaction (e.g., an ETH transfer via a smart contract) generates one `contract_result` row with `transaction_nonce = 0` and potentially many child rows with `transaction_nonce > 0` for each internal call frame. Each row carries an `amount` field representing the value moved in that call frame. When `internal=true` is set, all child rows are returned alongside the parent. A financial integration (exchange deposit detector, accounting system, bridge relayer) that iterates the results and sums `amount` will count the same underlying transfer multiple times — once per call frame — leading to inflated credit, double-crediting of deposits, or incorrect balance accounting. Severity is **Critical** for any system that uses this API as a source of truth for fund movements.

### Likelihood Explanation
The attack requires zero privileges: no API key, no authentication token, no special network access. The parameter name (`internal`) is self-documenting and discoverable from the OpenAPI/Swagger spec or by reading the public source code. The attack is a single HTTP GET request, is completely repeatable, and leaves no distinguishing trace beyond a normal API call. Any attacker who reads the public mirror-node documentation or source code can exploit this immediately.

### Recommendation
1. **Remove `filterKeys.INTERNAL` from `acceptedContractResultsParameters`** so that `buildAndValidateFilters` rejects the parameter entirely for public-facing endpoints, causing a 400 Bad Request if supplied.
2. If internal results must be accessible, gate the `internal` parameter behind an authenticated/privileged request path (e.g., a separate internal-only route, an operator API key, or a middleware that strips the parameter for unauthenticated callers).
3. As a defense-in-depth measure, document that `amount` values from internal sub-call rows must never be summed with top-level rows, and add a response field (e.g., `is_internal: true`) so consumers can filter correctly even if the parameter is ever re-exposed.

### Proof of Concept
```
# Step 1: Query without internal flag (safe, default behavior)
GET /api/v1/contracts/0.0.12345/results
# Returns only rows where transaction_nonce = 0 (top-level transactions)
# amount sum = X tinybars

# Step 2: Query with internal=true (exploit)
GET /api/v1/contracts/0.0.12345/results?internal=true
# Returns ALL rows including internal sub-calls (transaction_nonce > 0)
# amount sum = X * N tinybars  (N = number of internal call frames)

# A financial integration processing Step 2 results credits N times the actual deposit.
```

### Citations

**File:** rest/constants.js (L38-38)
```javascript
  INTERNAL: 'internal',
```

**File:** rest/controllers/contractController.js (L425-425)
```javascript
    let internal = false;
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
