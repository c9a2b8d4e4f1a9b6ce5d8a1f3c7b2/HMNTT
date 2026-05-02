### Title
Unauthenticated Resource Exhaustion via Arbitrary Numeric Account IDs in Token Allowance Endpoint

### Summary
The `getAccountTokenAllowances()` handler in `rest/controllers/tokenAllowanceController.js` accepts any valid numeric encoded entity ID, resolves it locally without a database existence check, and unconditionally issues a `token_allowance` table scan for the resolved ID. With no rate limiting present anywhere in the REST middleware stack, an unprivileged attacker can flood the database with empty scans using a large set of distinct valid numeric IDs, degrading mirror-node processing capacity.

### Finding Description

**Exact code path:**

`rest/controllers/tokenAllowanceController.js` line 69:
```js
const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
``` [1](#0-0) 

`EntityService.getEncodedId()` in `rest/service/entityService.js` lines 120–124:
```js
if (EntityId.isValidEntityId(entityIdString)) {
  const entityId = EntityId.parseString(entityIdString, {paramName});
  return entityId.evmAddress === null
    ? entityId.getEncodedId()          // ← pure local computation, NO DB lookup
    : await this.getEntityIdFromEvmAddress(entityId, requireResult);
``` [2](#0-1) 

For a plain numeric string (e.g. `"9999999999999999999"`), `isValidEntityId()` matches `encodedEntityIdRegex = /^-?\d{1,19}$/` and the branch returns `entityId.getEncodedId()` — a pure arithmetic operation — with **no database existence check**. [3](#0-2) [4](#0-3) 

Control then returns to the controller (line 72), which calls:
```js
const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
``` [5](#0-4) 

`TokenAllowanceService.getAccountTokenAllowances()` unconditionally executes:
```sql
SELECT * FROM token_allowance WHERE owner = $1 AND amount > 0 ...
```
against the database for whatever encoded ID was supplied. [6](#0-5) 

**Root cause:** The numeric-ID branch of `getEncodedId()` skips the entity-existence check that the alias and EVM-address branches perform (lines 125–126 of `entityService.js`). Any integer in the 64-bit signed range is accepted and forwarded directly to the DB layer. [7](#0-6) 

**Why the LRU cache does not help:** `parseCached()` in `entityId.js` caches only the *parsed EntityId object*, not the database query result. Each unique ID hits the cache once and then still triggers a fresh DB scan on every subsequent request. [8](#0-7) 

**No rate limiting:** A grep across all `rest/**/*.js` files for `throttle`, `rateLimit`, `rate_limit`, `maxRequests`, and `requestLimit` returns zero matches. The middleware index exposes no throttling layer.


### Impact Explanation
An attacker can generate an unbounded set of distinct valid 19-digit numeric IDs (the valid range spans the full signed 64-bit integer space), each producing a unique cache key and a unique DB query. Because the `token_allowance` table is indexed on `owner`, each query is a fast index scan returning zero rows, but at sufficient request volume (thousands of concurrent requests from a botnet or a single high-throughput client) the aggregate I/O and connection-pool pressure degrades database throughput for all mirror-node consumers, including the ingestion pipeline that feeds consensus data. This matches the "≥30% processing-node degradation" severity tier.

### Likelihood Explanation
No authentication, API key, or rate limit is required. The attack is fully scriptable: generate sequential or random 19-digit integers, issue HTTP GET requests to `/api/v1/accounts/{id}/allowances/tokens`, and repeat. A single commodity machine can sustain thousands of requests per second. The attack is repeatable, stateless, and requires zero knowledge of the target system beyond the public API spec.

### Recommendation
1. **Add an entity-existence pre-check for numeric IDs** in `EntityService.getEncodedId()`: after computing the encoded ID, call `isValidAccount(encodedId)` (already implemented in `entityService.js` line 60) and throw `NotFoundError` if the account does not exist, before proceeding to the allowance query.
2. **Implement rate limiting** at the Express middleware layer (e.g. `express-rate-limit`) scoped per source IP, applied globally or at least on all `/accounts/:id/allowances/*` routes.
3. **Cache negative (empty) DB results** for the allowance query with a short TTL so repeated requests for the same non-existent ID do not re-hit the database.

### Proof of Concept
```bash
# Generate 10 000 distinct non-existent numeric IDs and fire requests concurrently
for i in $(seq 9000000000000000000 9000000000000010000); do
  curl -s "https://<mirror-node>/api/v1/accounts/${i}/allowances/tokens" &
done
wait
```
Each request passes `isValidEntityId()`, bypasses the existence check, and issues a `SELECT * FROM token_allowance WHERE owner = ${i} AND amount > 0` query. With no rate limiting, all queries execute concurrently, exhausting DB connection pool and degrading throughput for legitimate traffic.

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L68-72)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
    const query = this.extractTokenMultiUnionQuery(filters, accountId);
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
```

**File:** rest/service/entityService.js (L120-124)
```javascript
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/service/entityService.js (L125-127)
```javascript
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
```

**File:** rest/entityId.js (L38-38)
```javascript
const encodedEntityIdRegex = /^-?\d{1,19}$/;
```

**File:** rest/entityId.js (L133-137)
```javascript
const isValidEntityId = (entityId, allowEvmAddress = true, evmAddressType = constants.EvmAddressType.ANY) => {
  if ((typeof entityId === 'string' && entityIdRegex.test(entityId)) || encodedEntityIdRegex.test(entityId)) {
    // Accepted forms: shard.realm.num, realm.num, or encodedId
    return true;
  }
```

**File:** rest/entityId.js (L314-333)
```javascript
const parseCached = (id, allowEvmAddress, evmAddressType, error) => {
  const key = `${id}_${allowEvmAddress}_${evmAddressType}`;
  const value = cache.get(key);
  if (value) {
    return value;
  }

  if (!isValidEntityId(id, allowEvmAddress, evmAddressType)) {
    throw error();
  }
  const [shard, realm, num, evmAddress] =
    id.includes('.') || isValidEvmAddressLength(id.length) ? parseFromString(id, error) : parseFromEncodedId(id, error);
  if (evmAddress === null && (num > maxNum || realm > maxRealm || shard > maxShard)) {
    throw error();
  }

  const entityId = of(shard, realm, num, evmAddress);
  cache.set(key, entityId);
  return entityId;
};
```

**File:** rest/service/tokenAllowanceService.js (L86-90)
```javascript
  async getAccountTokenAllowances(query) {
    const {sqlQuery, params} = this.getQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    return rows.map((ta) => new TokenAllowance(ta));
  }
```
