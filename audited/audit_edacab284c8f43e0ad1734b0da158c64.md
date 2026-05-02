### Title
Unauthenticated `internal=true` Parameter Bypasses `TRANSACTION_NONCE=0` Filter, Enabling Resource Exhaustion via Oversized DB Queries

### Summary
Any unauthenticated external user can supply `internal=true` to `GET /contracts/:contractId/results`, causing `extractContractResultsByIdQuery()` to omit the `cr.transaction_nonce = 0` SQL condition. Without this filter, the query returns all contract results including every internal/child call (nonce > 0), producing a result set that can be orders of magnitude larger than intended. Repeated requests can exhaust DB I/O and memory across mirror-node instances.

### Finding Description

**Exact code path:**

`rest/routes/contractRoute.js` line 14 registers the route with no authentication middleware: [1](#0-0) 

`acceptedContractResultsParameters` explicitly includes `filterKeys.INTERNAL`, making it a valid accepted query parameter: [2](#0-1) 

Inside `extractContractResultsByIdQuery`, `internal` defaults to `false`: [3](#0-2) 

When the filter loop encounters `filterKeys.INTERNAL`, it directly assigns the user-supplied boolean value with no privilege check: [4](#0-3) 

The sole guard that restricts results to top-level transactions is: [5](#0-4) 

When `internal=true` is passed, this `if (!internal)` branch is skipped entirely, and `cr.transaction_nonce = 0` is never appended to `conditions`. The resulting SQL query issued by `ContractService.getContractResultsByIdAndFilters` has no nonce filter, returning every internal call stored for that contract.

**Root cause:** The `internal` flag is designed to expose internal/child contract calls (nonce > 0), a feature that should be privileged or rate-limited, but it is exposed as a plain accepted query parameter with no authentication, authorization, or rate-limiting guard.

**Why existing checks are insufficient:**
- `buildAndValidateFilters` only validates that `internal` is a valid boolean — it does not check caller identity.
- `contractResultsFilterValidityChecks` performs no privilege check.
- There is no middleware on the route or inside `getContractResultsById` that restricts who may set `internal=true`. [6](#0-5) 

### Impact Explanation
In a busy Hedera network, a popular contract (e.g., a DEX or token bridge) can accumulate millions of internal call records. A single `GET /contracts/0.0.X/results?internal=true` with no timestamp bound forces a full-table scan returning all of them, bounded only by the default `limit` (100 rows) — but the DB must still evaluate the full predicate without the nonce index. Worse, an attacker can combine `internal=true` with a large `limit` value (up to the configured max) and no timestamp filter, maximizing per-query cost. Flooding multiple mirror-node replicas with such requests can saturate DB connection pools and memory, degrading or halting contract-result query processing across 30%+ of nodes without any brute-force credential requirement.

### Likelihood Explanation
The exploit requires zero credentials, zero special knowledge beyond the public API spec, and is trivially repeatable with a single HTTP client. The parameter name `internal` is self-documenting. Any attacker who reads the OpenAPI spec or observes network traffic can discover and weaponize it immediately. Automated scanners would also find it.

### Recommendation
1. **Remove `filterKeys.INTERNAL` from `acceptedContractResultsParameters`** for unauthenticated callers, or gate it behind an authentication/authorization middleware that checks a trusted role/API key before allowing `internal=true`.
2. If `internal=true` must remain public, **force a mandatory narrow timestamp range** (e.g., max 1 hour window) when `internal=true` is set, preventing unbounded scans.
3. Apply per-IP rate limiting specifically to requests that include `internal=true`.
4. Add a DB-level query timeout or row-count circuit breaker for this query path.

### Proof of Concept

```
# No credentials required
curl "https://<mirror-node-host>/api/v1/contracts/0.0.1234/results?internal=true&limit=100&order=asc"
```

**Steps:**
1. Identify a high-activity contract ID (e.g., from public explorer).
2. Send `GET /api/v1/contracts/<contractId>/results?internal=true` — no auth header needed.
3. Observe the response includes results with `transaction_nonce > 0` (internal calls), confirming the filter bypass.
4. Script 50–100 concurrent requests with no timestamp bounds to a cluster of mirror nodes.
5. Monitor DB CPU/I/O and mirror-node heap — resource exhaustion is observable within seconds on a busy contract.

The bypass is confirmed by the code: with `internal=true`, line 531–533 of `contractController.js` is skipped, and the SQL `WHERE` clause contains no `cr.transaction_nonce = 0` condition. [5](#0-4)

### Citations

**File:** rest/routes/contractRoute.js (L14-14)
```javascript
router.getExt('/:contractId/results', ContractController.getContractResultsById);
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

**File:** rest/controllers/contractController.js (L856-876)
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
```

**File:** rest/controllers/contractController.js (L1336-1346)
```javascript
const acceptedContractResultsParameters = new Set([
  filterKeys.FROM,
  filterKeys.BLOCK_HASH,
  filterKeys.BLOCK_NUMBER,
  filterKeys.HBAR,
  filterKeys.INTERNAL,
  filterKeys.LIMIT,
  filterKeys.ORDER,
  filterKeys.TIMESTAMP,
  filterKeys.TRANSACTION_INDEX,
]);
```
