### Title
Unbounded Sequential DB Lookups via Multiple `from=` EVM Address Filters in `getContractResultsById`

### Summary
The `extractContractResultsByIdQuery()` function in `rest/controllers/contractController.js` iterates over all `from=` query filters and, for each value that is an EVM address, issues a sequential `await`ed database query via `EntityService.getEncodedId()`. There is no cap on the number of `from=` parameters accepted per request. An unauthenticated attacker can craft requests with many EVM-address `from=` values and flood the service with concurrent such requests, exhausting the database connection pool and causing sustained service degradation across mirror-node instances.

### Finding Description
**Exact code path:**

`rest/routes/contractRoute.js` line 14 routes `GET /:contractId/results` to `ContractController.getContractResultsById`.

`getContractResultsById` (lines 856–892) calls `this.extractContractResultsByIdQuery(filters, contractId)` at line 871.

Inside `extractContractResultsByIdQuery` (lines 415–542), the filter loop at lines 439–484 handles `filterKeys.FROM`:

```js
// contractController.js lines 441-453
case filterKeys.FROM:
  if (EntityId.isValidEvmAddress(filter.value)) {
    filter.value = await EntityService.getEncodedId(filter.value);   // ← DB query per address
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
```

`EntityService.getEncodedId()` (lines 118–137 of `rest/service/entityService.js`) calls `getEntityIdFromEvmAddress()` (lines 90–104), which executes:

```sql
SELECT id FROM entity WHERE deleted <> true AND evm_address = $1
```

Each `from=<evmAddress>` parameter triggers one `await`ed (sequential) database round-trip **before** the main contract-results query is issued. Because the loop `await`s each call, N addresses in one request produce N sequential DB queries, each occupying a connection slot for its duration.

**Root cause / failed assumption:** `utils.buildAndValidateFilters` (called at line 376) validates the *format* of each filter value but imposes **no limit on the count** of `from=` parameters. The code assumes callers will supply at most one or two `from=` values; there is no guard.

**Why existing checks are insufficient:**
- `contractResultsFilterValidityChecks` (lines 273–279) only adds a special rule for `BLOCK_NUMBER`; it does not bound the cardinality of `FROM` filters.
- `utils.buildAndValidateFilters` validates each filter individually; it does not reject requests with more than N filters of the same key.
- No rate-limiting or request-level timeout is visible in the controller or route layer.

### Impact Explanation
A single HTTP request with, e.g., 150 `from=<unique_evm_address>` values (well within typical URL-length limits of 8 KB) causes 150 sequential `SELECT` queries against the `entity` table before the main query runs. Sending 50–100 such requests concurrently keeps the database connection pool continuously saturated. Because the mirror-node REST service is stateless and horizontally scaled, an attacker targeting multiple instances simultaneously can degrade or deny service on a significant fraction of the mirror-node fleet, preventing legitimate users from querying contract results. The `entity` table lookup is not cached at the application layer, so every EVM address in every request hits the database.

### Likelihood Explanation
The endpoint requires no authentication. Any external user can issue `GET /api/v1/contracts/<id>/results?from=<addr1>&from=<addr2>&...` with arbitrarily many `from=` values. The attack is trivially scriptable, requires no special knowledge beyond the public API documentation, and is repeatable indefinitely. The only practical constraint is URL length (≈8 KB), which still allows ~150–180 EVM-address values per request.

### Recommendation
1. **Cap the number of repeated filter values**: In `utils.buildAndValidateFilters` or in `extractContractResultsByIdQuery`, reject (HTTP 400) any request that supplies more than a small fixed maximum (e.g., 5–10) values for the same filter key.
2. **Batch the EVM-address lookups**: Collect all EVM-address `from=` values first, then resolve them in a single `WHERE evm_address = ANY($1)` query instead of N sequential queries.
3. **Apply rate limiting** at the API gateway or middleware layer for this endpoint.

### Proof of Concept
```bash
# Build a URL with 150 distinct EVM addresses as from= filters
BASE="http://<mirror-node>/api/v1/contracts/0.0.1234/results"
PARAMS=$(python3 -c "
import random, sys
addrs = ['from=' + ''.join([hex(random.randint(0,15))[2:] for _ in range(40)]) for _ in range(150)]
print('&'.join(addrs))
")

# Send 80 concurrent requests
for i in $(seq 1 80); do
  curl -s "${BASE}?${PARAMS}" &
done
wait
```

Each of the 80 concurrent requests triggers 150 sequential `SELECT id FROM entity WHERE evm_address = $1` queries. With a typical connection pool of 10–20 connections per node, this saturates the pool across multiple mirror-node instances, causing connection-wait timeouts for legitimate traffic. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/controllers/contractController.js (L439-454)
```javascript
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

**File:** rest/routes/contractRoute.js (L14-14)
```javascript
router.getExt('/:contractId/results', ContractController.getContractResultsById);
```
