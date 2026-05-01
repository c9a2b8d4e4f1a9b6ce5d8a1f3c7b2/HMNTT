### Title
Unauthenticated EVM Address Lookup Doubles DB Load Per Request, Enabling Griefing via Sustained Volume

### Summary
Any unauthenticated caller can send `GET /accounts/:evmAddress` with a valid 40-hex-character EVM address, causing `EntityService.getEncodedId()` to unconditionally execute a preliminary `entityFromEvmAddressQuery` DB round-trip before the main account query runs. Because the REST module has no IP-based rate limiting and the response cache is trivially bypassed by rotating EVM addresses, an attacker can sustain a 2× DB query load per request indefinitely with no cost to themselves.

### Finding Description

**Code path:**

`rest/accounts.js:399` — `getOneAccount()` calls `EntityService.getEncodedId()` unconditionally for every request: [1](#0-0) 

`rest/service/entityService.js:118-124` — `getEncodedId()` checks `EntityId.isValidEntityId()`. A 40-hex EVM address passes this check, `EntityId.parseString()` sets `evmAddress` to non-null, and the code branches into `getEntityIdFromEvmAddress()`: [2](#0-1) 

`rest/service/entityService.js:90-103` — `getEntityIdFromEvmAddress()` executes `entityFromEvmAddressQuery` — a full `SELECT id FROM entity WHERE evm_address = $1` — as a dedicated DB round-trip: [3](#0-2) [4](#0-3) 

**Root cause:** When the path parameter is a numeric entity ID (e.g., `0.0.1234`), `entityId.evmAddress === null` and `getEncodedId()` returns immediately with no DB call. When it is an EVM address, a DB query is always issued first, before the main account query at line 487. This asymmetry means EVM-address requests cost 2 DB queries vs. 1 for numeric IDs.

**Why existing checks fail:**

1. **No rate limiting in the REST module.** The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module. The REST middleware chain (`authHandler.js`, `requestHandler.js`, `responseCacheHandler.js`) contains no IP-based or per-client rate limiting for unauthenticated users. [5](#0-4) 

2. **Response cache is trivially bypassed.** The cache key is `MD5(req.originalUrl)`. An attacker rotating through distinct valid EVM addresses (`0x0000000000000000000000000000000000000001`, `0x0000000000000000000000000000000000000002`, …) generates a unique cache key per request, so every request is a cache miss and hits the DB twice. [6](#0-5) 

### Impact Explanation
Each EVM-address request causes 2 DB queries instead of 1. An attacker sending N requests/second with rotating EVM addresses forces 2N DB queries/second. Since the Ethereum address space is 2^160, the attacker has an effectively unlimited supply of unique cache-busting addresses. This can exhaust DB connection pools, increase query latency for all users, and degrade or deny service to legitimate users — all with zero economic cost to the attacker. Severity: **Medium** (griefing/DoS, no data exfiltration or fund loss).

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no on-chain activity. Any external actor with HTTP access to the mirror node REST API can execute it. The only barrier is network bandwidth, which is trivially available. The attack is fully repeatable and automatable with a simple script.

### Recommendation
1. **Add rate limiting to the REST module** — implement per-IP request throttling (e.g., via `express-rate-limit`) in the middleware chain, applied before route handlers.
2. **Cache the EVM-address-to-entity-ID mapping** — introduce an in-process or Redis-backed cache in `getEntityIdFromEvmAddress()` so repeated lookups for the same EVM address do not hit the DB.
3. **Consider input normalization** — normalize EVM addresses to lowercase before cache-key generation so case variants of the same address share a cache entry.

### Proof of Concept
```bash
# Generate and send requests with rotating EVM addresses (no auth required)
for i in $(seq 1 10000); do
  ADDR=$(printf "0x%040x" $i)
  curl -s "https://<mirror-node>/api/v1/accounts/$ADDR" &
done
wait
```
Each request is a cache miss (unique URL → unique MD5 key) and triggers two DB queries: `entityFromEvmAddressQuery` followed by the main entity/balance query. At sustained volume this doubles DB load compared to equivalent numeric-ID requests.

### Citations

**File:** rest/accounts.js (L399-399)
```javascript
  const encodedId = await EntityService.getEncodedId(req.params[constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-103)
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

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
