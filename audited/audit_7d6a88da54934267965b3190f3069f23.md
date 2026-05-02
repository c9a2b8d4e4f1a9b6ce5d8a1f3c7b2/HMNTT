### Title
Unauthenticated `internal=true` Filter Removes Selective Nonce Predicate, Enabling Amplified DB Scan on Contract Results Endpoint

### Summary
Any unprivileged external user can supply `internal=true` to the `/api/v1/contracts/results` endpoint. This parameter is accepted without authentication and, when set, suppresses the `transaction_nonce = 0` WHERE clause that normally restricts queries to top-level transactions only. On a busy network, internal transactions can outnumber top-level ones by orders of magnitude, causing the DB to scan a vastly larger row set — a meaningful amplification vector against a degraded read replica.

### Finding Description

**Code locations:**

`filterKeys.INTERNAL` is defined as the string `'internal'` and is explicitly included in the public-facing accepted parameter set: [1](#0-0) [2](#0-1) 

Validation in `filterValidityChecks` only checks that the value is a valid boolean — no authentication or privilege check exists: [3](#0-2) 

In `extractContractResultsByIdQuery`, the `internal` variable defaults to `false`. When the filter is present, it is set directly from user input: [4](#0-3) [5](#0-4) 

The critical branch: when `internal` is `false` (default), the condition `transaction_nonce = 0` is appended to the WHERE clause, restricting results to top-level transactions only. When `internal=true`, this condition is **entirely omitted**: [6](#0-5) 

The resulting SQL query always performs a `LEFT JOIN` against the `entity` table: [7](#0-6) 

Without `transaction_nonce = 0`, the planner must scan all `contract_result` rows (including every internal child call) before applying the LIMIT. A single Ethereum transaction can produce hundreds of internal calls, so the ratio of internal-to-top-level rows can be 100:1 or higher on active contracts.

### Impact Explanation

On a healthy replica the extra scan is expensive but survivable. On a **degraded replica** (reduced I/O throughput, replication lag, partial index unavailability), repeated unauthenticated requests with `internal=true` and no timestamp bounds force full or near-full sequential scans of `contract_result` joined to `entity`. This can saturate connection pools, spike CPU/IO, and cause query timeouts that cascade to other API consumers. The LIMIT clause does not prevent the scan cost — it only limits rows returned after the scan.

### Likelihood Explanation

The exploit requires zero credentials. The parameter name (`internal`) is self-documenting and visible in any OpenAPI/Swagger spec or by reading the source. An attacker can script concurrent requests trivially. The scenario is most dangerous during an already-degraded partition, exactly when operators have reduced capacity to respond.

### Recommendation

1. **Require authentication or an operator-controlled feature flag** before accepting `internal=true`. If internal transactions are a debug/operator feature, gate the parameter behind an API key or a config flag (`config.query.internal.enabled`).
2. **Enforce a mandatory timestamp range** when `internal=true` is supplied (similar to how `transaction.index` requires `block.number` or `block.hash`). Add a dependency check in `filterDependencyCheck`.
3. **Apply a stricter per-IP rate limit** on the `/contracts/results` endpoint, independent of the global limit.
4. **Set a DB statement timeout** on the read-replica connection pool for REST API queries.

### Proof of Concept

```
# No credentials required. Repeat concurrently to amplify load.
GET /api/v1/contracts/results?internal=true&limit=100
```

Preconditions: a mirror node with a non-trivial number of internal contract calls ingested (any mainnet/testnet mirror node qualifies).

Trigger: send N concurrent requests (e.g., `ab -n 500 -c 50`) to the above URL during a replica degradation event (simulated by throttling disk I/O or inducing replication lag).

Result: the DB replica executes full or near-full scans of `contract_result ⋈ entity` without the selective `transaction_nonce = 0` predicate, exhausting available I/O and connection slots on the degraded node.

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

**File:** rest/utils.js (L327-329)
```javascript
    case constants.filterKeys.INTERNAL:
      ret = isValidBooleanOpAndValue(op, val);
      break;
```

**File:** rest/service/contractService.js (L80-83)
```javascript
  static joinContractResultWithEvmAddress = `
      left join ${Entity.tableName} ${Entity.tableAlias}
      on ${Entity.getFullName(Entity.ID)} = ${ContractResult.getFullName(ContractResult.CONTRACT_ID)}
   `;
```
