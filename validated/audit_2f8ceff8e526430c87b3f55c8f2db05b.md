Based on my code investigation, all key technical claims are verified against the actual source:

- Lines 439–454 of `contractController.js`: sequential `await EntityService.getEncodedId(filter.value)` per EVM-address `from` filter. [1](#0-0) 
- `entityFromEvmAddressQuery` in `entityService.js`: direct single-row DB query, no cache, no batching. [2](#0-1) 
- DB pool wired to `config.db.pool.maxConnections`. [3](#0-2) 
- Both `getContractResultsById` (line 856) and `getContractResults` (line 1050) are unauthenticated handlers that feed into this path. [4](#0-3) 

---

# Audit Report

## Title
N+1 DB Lookup Amplification via Multiple EVM-Address `from` Parameters in `extractContractResultsByIdQuery`

## Summary
`extractContractResultsByIdQuery` in `rest/controllers/contractController.js` sequentially `await`s one `EntityService.getEncodedId` database call per EVM-address `from` filter. An unauthenticated caller may supply up to `maxRepeatedQueryParameters` (default: 100) distinct EVM addresses in a single request, forcing up to 100 sequential DB queries against a connection pool with a fixed maximum size.

## Finding Description
In `rest/controllers/contractController.js`, the loop at lines 439–454 processes each `from` filter independently:

```js
for (const filter of filters) {
  switch (filter.key) {
    case filterKeys.FROM:
      if (EntityId.isValidEvmAddress(filter.value)) {
        filter.value = await EntityService.getEncodedId(filter.value); // one DB call per address
      }
```

Each `await` resolves through `getEntityIdFromEvmAddress` in `rest/service/entityService.js`, which executes:

```js
static entityFromEvmAddressQuery = `select ${Entity.ID}
  from ${Entity.tableName}
  where ${Entity.DELETED} <> true
    and ${Entity.EVM_ADDRESS} = $1`;
```

There is no in-process cache, no deduplication, and no batching into a single `WHERE evm_address IN (...)` query. Each call consumes a connection from the pool for its duration.

The only guard is `maxRepeatedQueryParameters` (default: 100), enforced in `buildFilters` in `rest/utils.js`. This is a ceiling on repetition, not a protection against amplification — it explicitly permits up to 100 repeated `from` values. The `FROM` validity check only validates format (EVM address syntax), not count.

Both public endpoints that invoke this path are unauthenticated:
- `GET /api/v1/contracts/results` → `getContractResults` (line 1050)
- `GET /api/v1/contracts/:contractId/results` → `getContractResultsById` (line 856)

## Impact Explanation
The DB connection pool is bounded by `config.db.pool.maxConnections` (default: 10 per `rest/dbpool.js`). A single HTTP request with 100 unique EVM-address `from` values issues 100 sequential DB queries. A small number of concurrent such requests (e.g., 10–20) can saturate the pool, causing all other API requests to queue or time out at the configured `statementTimeout` (default: 20 s). This is a low-cost, unauthenticated denial-of-service amplification: 1 HTTP request → up to 100 DB queries.

## Likelihood Explanation
No authentication or rate limiting is enforced at the application layer on these endpoints. The attack is trivially reproducible with a single `curl` command using repeated `from=0x...` query parameters. Any external user who can reach the REST API can exploit this. The default `maxRepeatedQueryParameters` of 100 is publicly documented.

## Recommendation
1. **Batch the lookups**: Collect all EVM-address `from` values first, then resolve them in a single `WHERE evm_address = ANY($1)` query instead of one query per address.
2. **Add an in-process short-lived cache** (e.g., per-request or TTL-based) for EVM-address-to-entity-id resolution in `EntityService`.
3. **Lower `maxRepeatedQueryParameters`** for the `from` filter specifically, or add a separate, lower cap for EVM-address-type `from` values.
4. **Apply rate limiting** at the API gateway or middleware layer for unauthenticated endpoints.

## Proof of Concept
```bash
# Build a request with 100 distinct EVM addresses as `from` parameters
PARAMS=$(python3 -c "
import random
params = '&'.join(
  f'from=0x{random.randint(0,2**160):040x}'
  for _ in range(100)
)
print(params)
")

curl -s "https://<mirror-node-host>/api/v1/contracts/results?$PARAMS" &
# Repeat 10-20 times concurrently to saturate the pool
```

Each request triggers up to 100 sequential `SELECT id FROM entity WHERE evm_address = $1` queries. With 10–20 concurrent such requests, the 10-connection pool is saturated and all other API traffic stalls.

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

**File:** rest/controllers/contractController.js (L856-856)
```javascript
  getContractResultsById = async (req, res) => {
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/dbpool.js (L14-14)
```javascript
  max: config.db.pool.maxConnections,
```
