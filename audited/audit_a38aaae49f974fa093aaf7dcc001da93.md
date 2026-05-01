### Title
Unauthenticated Alias-Based DB Connection Pool Exhaustion via Account Route

### Summary
The REST API's account route exposes endpoints that accept alias-format path parameters (e.g., `KGNABD5L3ZGSRVUCSPDR7TONZSRY3D5OMEBKQMVTD2AC6JL72HMQ`) which unconditionally trigger a database query with no caching and no application-level rate limiting. Because the default connection pool is capped at 10 connections and all REST API endpoints share the same pool, a single unauthenticated attacker flooding these endpoints with unique valid aliases can exhaust the pool and render the entire mirror node REST API unavailable.

### Finding Description

**Code path:**

`rest/routes/accountRoute.js` line 12 defines the route parameter: [1](#0-0) 

Every sub-route (nfts, rewards, allowances/crypto, allowances/tokens, tokens) immediately calls `EntityService.getEncodedId()` with the raw path parameter: [2](#0-1) [3](#0-2) 

Inside `getEncodedId()`, when the input passes `AccountAlias.isValid()`, it unconditionally calls `getAccountIdFromAlias()` → `getAccountFromAlias()` → `super.getRows()` → a live DB query: [4](#0-3) [5](#0-4) 

The query hits the database directly with no result caching: [6](#0-5) 

`BaseService.getRows()` acquires a connection from the global pool: [7](#0-6) 

The pool is initialized with a hard cap of `config.db.pool.maxConnections` connections, defaulting to **10**: [8](#0-7) [9](#0-8) 

**Root cause:** There is no application-level rate limiting in the Node.js REST API middleware stack (`requestHandler.js`, `authHandler.js`, etc. — none implement per-IP or global request throttling). The alias-to-entity-id resolution path has no cache layer (the `entityId` cache in `rest/entityId.js` covers only numeric/EVM-address parsing, not alias→DB lookups). Every unique alias value forces a fresh DB query. With only 10 pool connections shared across all REST endpoints, concurrent alias-flooding saturates the pool.

**Failed assumption:** The design assumes that alias lookups are rare or that infrastructure-level controls (e.g., Traefik rate limiting in Helm charts) will always be present. Neither is guaranteed in default deployments, and the application provides no defense-in-depth.

### Impact Explanation

When all 10 pool connections are held by alias-lookup queries, every other REST API endpoint (transactions, balances, tokens, contracts, etc.) that needs a DB connection will block waiting up to `connectionTimeoutMillis` (default 20 000 ms) before returning an error. This causes complete REST API unavailability — not just for account endpoints — for the duration of the attack. The `statement_timeout` of 20 seconds means the attacker must sustain ~10 concurrent requests continuously, which is trivially achievable from a single machine. [9](#0-8) 

### Likelihood Explanation

**Preconditions:** None. No authentication, no API key, no prior knowledge of valid aliases required. Any valid base32 string matching `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/` passes `AccountAlias.isValid()` and triggers a DB query. [10](#0-9) 

**Trigger:** Send ≥10 concurrent HTTP GET requests to `/api/v1/accounts/{unique_alias}/nfts` with distinct alias values (e.g., `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB`, …). Each request holds a pool connection for the duration of the DB query. Sustaining this rate keeps the pool permanently exhausted.

**Repeatability:** Fully repeatable, scriptable with `curl`/`ab`/`wrk` from a single host. No special network position required.

### Recommendation

1. **Add application-level rate limiting** to the Node.js REST API (e.g., `express-rate-limit` per IP or globally) before any DB-touching handler runs.
2. **Cache alias→entity-id resolution results** in `EntityService.getAccountFromAlias()` using the existing `entityId` cache infrastructure (already configured with `maxSize: 100000`, `maxAge: 1800s`).
3. **Increase the default pool size** or add a per-request concurrency semaphore to bound the number of simultaneous alias-lookup DB queries.
4. **Add a fast pre-check** that rejects aliases exceeding a maximum byte length before any DB access.

### Proof of Concept

```bash
# Generate 500 unique valid base32 aliases and flood the endpoint concurrently
for i in $(seq 1 500); do
  ALIAS=$(python3 -c "import base64, os; print(base64.b32encode(os.urandom(20)).decode().rstrip('='))")
  curl -s "http://<mirror-node-host>:5551/api/v1/accounts/${ALIAS}/nfts" &
done
wait
# All 10 DB connections are now held; subsequent requests to ANY endpoint
# (e.g., /api/v1/transactions) will time out or return 500 errors.
curl "http://<mirror-node-host>:5551/api/v1/transactions"
# Expected: connection timeout or pool exhaustion error
```

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

**File:** rest/controllers/accountController.js (L90-92)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
```

**File:** rest/controllers/accountController.js (L170-172)
```javascript
  listStakingRewardsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
```

**File:** rest/service/entityService.js (L17-20)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;
```

**File:** rest/service/entityService.js (L42-53)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);

    if (isEmpty(rows)) {
      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching alias ${accountAlias}`);
      throw new Error(EntityService.multipleAliasMatch);
    }

    return new Entity(rows[0]);
  }
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

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
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
