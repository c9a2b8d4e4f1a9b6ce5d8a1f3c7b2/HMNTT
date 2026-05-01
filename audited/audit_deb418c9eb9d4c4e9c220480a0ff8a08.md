### Title
Unbounded DB Lookup Amplification via Account Alias Path Parameter on All Account Sub-Routes

### Summary
Every account sub-route in `rest/routes/accountRoute.js` accepts an alias string as the `:idOrAliasOrEvmAddress` path parameter. When an alias is supplied, `EntityService.getEncodedId()` unconditionally executes a database query (`entityFromAliasQuery`) against the `entity` table on every request, with no per-alias result caching. Because numeric-ID requests require zero DB queries for ID resolution (pure in-memory computation), an attacker flooding the five sub-routes with unique valid alias strings forces at least one extra DB query per request, easily exceeding a 30% increase in DB I/O over a numeric-ID baseline.

### Finding Description

**Exact code path:**

`rest/routes/accountRoute.js` lines 15–19 register five sub-routes, all parameterized by `:idOrAliasOrEvmAddress`: [1](#0-0) 

Each handler immediately calls `EntityService.getEncodedId()` with the raw path parameter, e.g.: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

Inside `getEncodedId()`, the branching logic is: [7](#0-6) 

- If the input is a numeric entity ID (`EntityId.isValidEntityId()` → true), the encoded ID is computed **in memory** — zero DB queries.
- If the input is a valid alias (`AccountAlias.isValid()` → true), `getAccountIdFromAlias()` is called, which calls `getAccountFromAlias()`, which executes:

```sql
SELECT id FROM entity
WHERE coalesce(deleted, false) <> true
  AND alias = $1
``` [8](#0-7) 

**Root cause:** There is no in-process cache for alias→ID resolution results. The response-level cache (`responseCacheHandler.js`) only short-circuits the full HTTP response for repeated identical URLs; it does not prevent the alias DB lookup from executing on cache misses. [9](#0-8) 

**Alias validity check:** `AccountAlias.isValid()` accepts any string matching `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/` — the base32 alphabet. An attacker can trivially generate an unbounded number of syntactically valid alias strings (e.g., `AAAAAAA`, `AAAAAAB`, `AAAAAAC`, …). [10](#0-9) 

### Impact Explanation

For every numeric-ID request, ID resolution costs 0 DB queries. For every alias request, it costs 1 additional `SELECT` against the `entity` table. If an attacker directs all traffic to alias-parameterized URLs with unique alias strings (bypassing the response cache), the DB query count per request at least doubles relative to the numeric-ID baseline — a ≥100% increase in DB I/O, well above the 30% threshold. The `entity` table is central to the mirror node; sustained extra load on it degrades all other queries sharing the same DB connection pool and I/O bandwidth.

### Likelihood Explanation

No authentication or privilege is required. The five affected sub-routes are public REST endpoints. Generating valid base32 alias strings requires no knowledge of the system — any sequence of uppercase A–Z and 2–7 characters passes `AccountAlias.isValid()`. A single attacker with a modest HTTP client can sustain thousands of unique-alias requests per second. No rate limiting is present in the REST module (the `ThrottleConfiguration` found applies only to the `web3` module). [11](#0-10) 

### Recommendation

1. **Cache alias→ID resolution results** in the existing in-process or Redis cache with a short TTL (e.g., 5–30 s), keyed by the alias string. This eliminates repeated DB hits for the same alias.
2. **Apply rate limiting** to the REST API layer (not just `web3`), per IP or globally, to bound the number of alias lookups per time window.
3. **Reject non-existent aliases early** with a short-lived negative cache entry so that flood traffic with random aliases does not reach the DB at all.

### Proof of Concept

```bash
# Generate N unique valid base32 alias strings and hammer one sub-route
for i in $(seq 1 10000); do
  ALIAS=$(python3 -c "import random,string; print(''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=10)))")
  curl -s "https://<mirror-node>/api/v1/accounts/${ALIAS}/nfts" &
done
wait
```

**Preconditions:** No credentials needed; any public mirror node instance.  
**Trigger:** Each request with a unique alias string is a response-cache miss → `entityFromAliasQuery` executes against the DB.  
**Result:** DB query rate increases proportionally to request rate; at sustained load, DB I/O rises ≥30% above the numeric-ID baseline, degrading overall mirror node performance.

### Citations

**File:** rest/routes/accountRoute.js (L12-19)
```javascript
const getPath = (path) => `/:${filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}/${path}`;

const resource = 'accounts';
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
router.getExt(getPath('rewards'), AccountController.listStakingRewardsByAccountId);
router.getExt(getPath('allowances/crypto'), CryptoAllowanceController.getAccountCryptoAllowances);
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
router.getExt(getPath('tokens'), TokenController.getTokenRelationships);
```

**File:** rest/controllers/accountController.js (L91-91)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/accountController.js (L171-171)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/cryptoAllowanceController.js (L77-77)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/tokenAllowanceController.js (L69-69)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/tokenController.js (L67-67)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/service/entityService.js (L17-20)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;
```

**File:** rest/service/entityService.js (L118-127)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
```

**File:** rest/middleware/responseCacheHandler.js (L40-48)
```javascript
const responseCacheCheckHandler = async (req, res) => {
  const startTime = res.locals[requestStartTime] || Date.now();
  const responseCacheKey = cacheKeyGenerator(req);
  const cachedTtlAndValue = await getCache().getSingleWithTtl(responseCacheKey);

  if (!cachedTtlAndValue) {
    res.locals[responseCacheKeyLabel] = responseCacheKey;
    return;
  }
```

**File:** rest/accountAlias.js (L10-43)
```javascript
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
const noShardRealmAccountAliasRegex = /^[A-Z2-7]+$/;
const {common} = getMirrorConfig();

class AccountAlias {
  /**
   * Creates an AccountAlias object.
   * @param {string|null} shard
   * @param {string|null} realm
   * @param {string} base32Alias
   */
  constructor(shard, realm, base32Alias) {
    this.shard = AccountAlias.validate(shard, common.shard, 'shard');
    this.realm = AccountAlias.validate(realm, common.realm, 'realm');
    this.alias = base32.decode(base32Alias);
    this.base32Alias = base32Alias;
  }

  static validate(num, configured, name) {
    if (!isNil(num) && BigInt(num) !== configured) {
      throw new InvalidArgumentError(`Unsupported ${name} ${num}`);
    }
    return configured;
  }

  /**
   * Checks if the accountAlias string is valid
   * @param {string} accountAlias
   * @param {boolean} noShardRealm If shard realm is allowed as a part of the alias.
   * @return {boolean}
   */
  static isValid(accountAlias, noShardRealm = false) {
    const regex = noShardRealm ? noShardRealmAccountAliasRegex : accountAliasRegex;
    return typeof accountAlias === 'string' && regex.test(accountAlias);
```
