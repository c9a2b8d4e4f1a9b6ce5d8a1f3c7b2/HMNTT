### Title
Unauthenticated `from` EVM Address Filter Causes Extra DB Lookup Per Request on `/contracts/results`, Enabling DB Load Amplification

### Summary
In `rest/controllers/contractController.js`, the `extractContractResultsByIdQuery` function unconditionally calls `EntityService.getEncodedId()` — which executes a live database query — whenever the `from` query parameter contains a non-parsable EVM address. Because the `/contracts/results` endpoint requires no authentication, any external user can trigger this extra DB lookup on every request, doubling the number of database round-trips per request and degrading throughput under load.

### Finding Description

**Exact code path:**

In `rest/controllers/contractController.js`, `extractContractResultsByIdQuery` (called by both `getContractResults` at line 1067 and `getContractResultsById` at line 871) processes the `from` filter: [1](#0-0) 

```js
case filterKeys.FROM:
  if (EntityId.isValidEvmAddress(filter.value)) {
    filter.value = await EntityService.getEncodedId(filter.value);
  }
```

`EntityId.isValidEvmAddress` matches any string satisfying: [2](#0-1) 

```js
const evmAddressRegex = /^(0x)?[A-Fa-f0-9]{40}$/;
```

So any 40-hex-character string (with or without `0x`) passes the check.

Inside `EntityService.getEncodedId`: [3](#0-2) 

```js
if (EntityId.isValidEntityId(entityIdString)) {
  const entityId = EntityId.parseString(entityIdString, {paramName});
  return entityId.evmAddress === null
    ? entityId.getEncodedId()
    : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

For a **non-parsable** EVM address (i.e., one whose first 12 bytes do not encode shard/realm/num — any random 40-hex string qualifies), `entityId.evmAddress` is non-null, so `getEntityIdFromEvmAddress` is called: [4](#0-3) 

```js
async getEntityIdFromEvmAddress(entityId, requireResult = true) {
  const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

This executes a live `SELECT id FROM entity WHERE evm_address = $1` query.

When the EVM address resolves to a known entity, execution continues to `getContractResultsByIdAndFilters`: [5](#0-4) 

which executes a second DB query — the actual contract results query. This is the doubling.

**Root cause:** There is no caching layer between `EntityService.getEncodedId()` and the database. Every request with a non-parsable EVM address `from` value unconditionally issues a fresh `SELECT` against the `entity` table.

**Why existing checks are insufficient:** The only guard is `EntityId.isValidEvmAddress()`, which is a pure regex check — it does not prevent the DB lookup, it *triggers* it. There is no rate limiting on the REST Node.js service for this endpoint (the throttle found in the codebase applies only to the `web3` Java service for contract calls). [6](#0-5) 

### Impact Explanation
Each request to `GET /contracts/results?from=0x<valid_evm_address>` causes two sequential DB queries instead of one. An attacker sending a sustained flood of such requests doubles the effective DB query rate compared to requests without the `from` filter. Since the REST service has no per-IP or per-endpoint rate limiting, this is a straightforward DB amplification griefing vector. Under sufficient request volume, DB connection pool exhaustion or query queue saturation can degrade response times for all users of the mirror node REST API.

### Likelihood Explanation
The precondition is trivial: the attacker needs one valid EVM address that exists in the `entity` table. Such addresses are publicly discoverable via `GET /contracts` (the mirror node's own API). The attack requires no credentials, no special knowledge, and no on-chain activity. It is fully repeatable and automatable with standard HTTP tooling (e.g., `curl`, `ab`, `wrk`).

### Recommendation
1. **Cache entity EVM address lookups**: Introduce an in-process LRU or TTL cache in `EntityService.getEntityIdFromEvmAddress` so repeated lookups for the same address do not hit the DB.
2. **Apply rate limiting to the REST service**: Add per-IP request rate limiting (e.g., via an Express middleware like `express-rate-limit`) to the `/contracts/results` endpoint.
3. **Fail fast on non-existent addresses**: Consider passing `requireResult = false` to `getEncodedId` in the `from` filter path and short-circuiting with an empty result set rather than throwing, to avoid the DB round-trip for non-existent addresses entirely.

### Proof of Concept

1. Identify a valid contract EVM address from the mirror node:
   ```
   GET /api/v1/contracts?limit=1
   # note the evm_address field, e.g. 0x71eaa748d5252be68c1185588beca495459fdba4
   ```

2. Send a sustained flood of requests using that address as the `from` filter:
   ```bash
   while true; do
     curl -s "https://<mirror-node>/api/v1/contracts/results?from=0x71eaa748d5252be68c1185588beca495459fdba4" > /dev/null &
   done
   ```

3. Observe in DB metrics that each request generates two queries: one `SELECT id FROM entity WHERE evm_address = $1` and one `SELECT ... FROM contract_result cr LEFT JOIN entity e ...`, doubling the DB query rate compared to requests without the `from` filter.

### Citations

**File:** rest/controllers/contractController.js (L441-454)
```javascript
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

**File:** rest/controllers/contractController.js (L1072-1072)
```javascript
    const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
```

**File:** rest/entityId.js (L40-40)
```javascript
const evmAddressRegex = /^(0x)?[A-Fa-f0-9]{40}$/;
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-92)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
```

**File:** rest/service/entityService.js (L118-124)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```
