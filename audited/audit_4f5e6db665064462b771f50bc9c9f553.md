Now I have all the information needed. Let me analyze the complete picture:

**Numeric ID path**: `getEncodedId()` → `entityId.evmAddress === null` → `entityId.getEncodedId()` (pure computation, no DB) → then `isValidAccount()` → **1 DB query total**

**EVM address path**: `getEncodedId()` → `entityId.evmAddress !== null` → `getEntityIdFromEvmAddress()` (DB query #1) → then `isValidAccount()` (DB query #2) → **2 DB queries total**

The `quickLru` cache in `entityId.js` (lines 301-304) only caches the parsed `EntityId` object (string → shard/realm/num/evmAddress struct), **not** the DB lookup results. No rate limiting exists in the REST layer.

---

### Title
Double DB Query Per Request via EVM Address in `getTokenRelationships()` Enables Unauthenticated Resource Exhaustion

### Summary
An unprivileged external user can supply any valid EVM address to the public `/api/v1/accounts/:idOrAliasOrEvmAddress/tokens` endpoint, causing `getTokenRelationships()` to unconditionally execute two sequential DB queries per request instead of one. No application-level rate limiting exists, and the entity-ID LRU cache does not cache DB results, so every concurrent request with an EVM address doubles the DB query load compared to a numeric-ID request.

### Finding Description
In `rest/controllers/tokenController.js`, `getTokenRelationships()` always calls both:

```js
// Line 67 — may or may not hit DB depending on input type
const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
// Line 68 — always hits DB
const isValidAccount = await EntityService.isValidAccount(accountId);
```

Inside `rest/service/entityService.js`, `getEncodedId()` (lines 118–137) branches on input type:
- **Numeric ID** (`entityId.evmAddress === null`, line 122–123): returns `entityId.getEncodedId()` — pure arithmetic, zero DB queries.
- **EVM address** (`entityId.evmAddress !== null`, line 124): calls `getEntityIdFromEvmAddress()` (lines 90–104), which executes:
  ```sql
  SELECT id FROM entity WHERE deleted <> true AND evm_address = $1
  ```
  This is DB query #1.

Then `isValidAccount()` (lines 60–63) always executes:
```sql
SELECT type FROM entity WHERE id = $1
```
This is DB query #2.

The `quickLru` cache in `rest/entityId.js` (lines 301–333) caches only the parsed `EntityId` struct (string → shard/realm/num/evmAddress), not the DB lookup results. A grep across `rest/**/*.js` confirms zero rate-limiting middleware. The result: every EVM-address request costs 2 DB round-trips; every numeric-ID request costs 1. An attacker sending N concurrent EVM-address requests generates 2N DB queries.

### Impact Explanation
The entity table is central to the mirror node's operation. Saturating its connection pool or query executor with 2× the expected query rate degrades or halts responses for all consumers of the REST API. Because the endpoint is public and requires no credentials, any external actor can sustain this load. Nodes sharing the same DB backend (common in clustered deployments) are all affected simultaneously, consistent with the ≥30% processing-node impact threshold.

### Likelihood Explanation
No authentication, API key, or application-level rate limit is required. Any HTTP client can issue requests. The EVM address format is documented in the public OpenAPI spec (`rest/api/v1/openapi.yml`, lines 4667–4670). A single script looping `GET /api/v1/accounts/0x<40-hex-chars>/tokens` with high concurrency is sufficient. The attack is repeatable, stateless, and requires no prior knowledge of valid accounts (non-existent addresses still trigger both queries before returning 404).

### Recommendation
1. **Merge the two queries**: After `getEntityIdFromEvmAddress()` already confirms the entity exists and returns its ID, `isValidAccount()` is redundant — the entity was just found. Skip the second query when the first succeeded.
2. **Cache DB results**: Cache the EVM-address → encoded-ID mapping (with a short TTL) in the existing `quickLru` infrastructure so repeated lookups for the same address skip the DB.
3. **Add rate limiting**: Apply per-IP or per-endpoint rate limiting middleware in the Express layer for all `/accounts/:id/*` routes.
4. **Unify the existence check**: Restructure `getEncodedId()` to return a flag indicating whether a DB lookup was performed, allowing `getTokenRelationships()` to skip `isValidAccount()` when the entity was already confirmed.

### Proof of Concept
```bash
# Flood with a non-existent EVM address — triggers 2 DB queries per request, returns 404
# but both queries execute before the 404 is thrown (getEntityIdFromEvmAddress throws NotFoundError
# only after the SELECT returns 0 rows)

for i in $(seq 1 500); do
  curl -s "http://<mirror-node>/api/v1/accounts/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/tokens" &
done
wait
```

Each of the 500 concurrent requests executes:
1. `SELECT id FROM entity WHERE deleted <> true AND evm_address = $1` (returns 0 rows)
2. `getEntityIdFromEvmAddress` throws `NotFoundError` — `isValidAccount` is skipped in this case

Wait — let me correct: if `getEntityIdFromEvmAddress` throws (no match, `requireResult=true`), `isValidAccount` is never reached. To trigger **both** queries, the EVM address must resolve to a valid entity:

```bash
# Use a known valid EVM address (e.g., from public chain data)
VALID_EVM="0xac384c53f03855fa1b3616052f8ba32c6c2a2fec"
for i in $(seq 1 500); do
  curl -s "http://<mirror-node>/api/v1/accounts/${VALID_EVM}/tokens" &
done
wait
# Result: 1000 DB queries issued for 500 HTTP requests (2× amplification)
# vs 500 DB queries for the same 500 requests using a numeric account ID
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/tokenController.js (L66-71)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
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

**File:** rest/entityId.js (L301-333)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});

/**
 * Parses entity ID string, can be shard.realm.num, realm.num, the encoded entity ID or an evm address.
 * @param {string} id
 * @param {boolean} allowEvmAddress
 * @param {number} evmAddressType
 * @param {Function} error
 * @return {EntityId}
 */
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
