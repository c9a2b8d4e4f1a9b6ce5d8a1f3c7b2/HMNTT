### Title
Unauthenticated DB Connection Pool Exhaustion via Unique Alias Flooding on `/accounts/:idOrAliasOrEvmAddress/allowances/crypto`

### Summary
The `/api/v1/accounts/{idOrAliasOrEvmAddress}/allowances/crypto` endpoint accepts alias strings and unconditionally issues a database query for each unique alias via `getEncodedId()` → `getAccountIdFromAlias()` → `getAccountFromAlias()` → `entityFromAliasQuery`. There is no per-IP rate limiting and 404 responses (alias not found) are never cached, meaning an unauthenticated attacker can flood the endpoint with an unbounded stream of unique valid base32 alias strings, each consuming a connection from the finite DB pool, causing pool exhaustion and degrading all endpoints sharing that pool.

### Finding Description

**Exact code path:**

`rest/controllers/cryptoAllowanceController.js` line 77 calls `EntityService.getEncodedId(req.params[...])` unconditionally before any caching or rate-limiting check. [1](#0-0) 

`getEncodedId` in `rest/service/entityService.js` line 125–126 detects a valid alias string and calls `getAccountIdFromAlias` → `getAccountFromAlias`. [2](#0-1) 

`getAccountFromAlias` executes `entityFromAliasQuery` against the DB for every call: [3](#0-2) [4](#0-3) 

**Root cause — three failed assumptions:**

1. **No rate limiting.** A search of all `rest/` middleware reveals no `express-rate-limit` or equivalent. The `authHandler` only grants authenticated users a higher *response-size* limit; it does not throttle unauthenticated request rates. [5](#0-4) 

2. **404 responses are never cached.** `responseCacheUpdateHandler` only stores responses when `httpStatusCodes.isSuccess(res.statusCode)` is true. A non-existent alias returns HTTP 404, which is never written to Redis. Every unique alias therefore bypasses the cache entirely. [6](#0-5) 

3. **Finite DB connection pool.** The pool is bounded by `config.db.pool.maxConnections` with a hard `max` cap. Each alias lookup acquires a connection for the duration of the query. [7](#0-6) 

**Alias generation space is effectively unlimited.** `AccountAlias.isValid` accepts any string matching `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/`. An 8-character base32 string (e.g., `AAAAAAAA`, `AAAAAAAB`, …) has 32⁸ ≈ 10¹² unique values, all of which pass validation and reach the DB. [8](#0-7) [9](#0-8) 

### Impact Explanation

The DB pool is shared across every endpoint served by a mirror node replica. Exhausting it (all `maxConnections` slots occupied by alias-lookup queries) causes every subsequent request — transactions, balances, tokens, etc. — to queue until `connectionTimeoutMillis` expires and then fail with a DB error. Because the attack is stateless and requires no authentication, it can be directed simultaneously at multiple replicas. Degrading the DB pool of ≥30% of replicas meets the stated severity threshold of shutting down ≥30% of network processing capacity without brute-force actions.

### Likelihood Explanation

The attack requires only an HTTP client and knowledge of the public API (documented in the OpenAPI spec). Generating unique valid base32 strings is trivial. No credentials, tokens, or on-chain state are needed. The attack is repeatable indefinitely and can be automated with a simple loop. A single attacker with modest bandwidth (e.g., a few hundred concurrent connections) can saturate a default-sized pg pool.

### Recommendation

1. **Add per-IP rate limiting** at the Express middleware layer (e.g., `express-rate-limit`) applied globally before route handlers, with a low burst limit for unauthenticated callers.
2. **Cache alias-not-found (404) responses** in Redis with a short TTL (e.g., 5–10 s) so repeated lookups for the same non-existent alias do not hit the DB. The cache key already uses `req.originalUrl`, so this requires only relaxing the success-only guard in `responseCacheUpdateHandler`.
3. **Add a DB-level query timeout** specifically for alias lookups (already partially addressed by `statementTimeout`, but a shorter per-query hint for this path would reduce connection hold time).
4. **Consider an application-level alias lookup cache** (in-memory LRU or Redis) inside `getAccountFromAlias` to short-circuit repeated lookups for the same alias without touching the pool.

### Proof of Concept

```bash
# Generate unique 8-char base32 aliases and flood the endpoint concurrently
python3 - <<'EOF'
import subprocess, itertools, string

BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
TARGET = 'http://<mirror-node-host>/api/v1/accounts/{alias}/allowances/crypto'

# Generate 10,000 unique aliases
aliases = (''.join(c) for c in itertools.product(BASE32, repeat=8))

cmds = []
for i, alias in enumerate(aliases):
    if i >= 10000:
        break
    cmds.append(f'curl -s -o /dev/null "{TARGET.format(alias=alias)}" &')

# Fire all requests concurrently
script = '\n'.join(cmds) + '\nwait'
subprocess.run(['bash', '-c', script])
EOF
```

**Expected result:** The DB connection pool on the targeted replica(s) is saturated. Concurrent legitimate requests to any endpoint on those replicas begin returning 500/503 errors or timing out after `connectionTimeoutMillis` ms, demonstrating ≥30% processing capacity degradation when applied across replicas.

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L76-78)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
```

**File:** rest/service/entityService.js (L17-20)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;
```

**File:** rest/service/entityService.js (L42-43)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
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

**File:** rest/middleware/responseCacheHandler.js (L90-97)
```javascript
const responseCacheUpdateHandler = async (req, res) => {
  const responseCacheKey = res.locals[responseCacheKeyLabel];
  const responseBody = res.locals[responseBodyLabel];
  const isUnmodified = res.statusCode === httpStatusCodes.UNMODIFIED.code;

  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
    if (ttl > 0) {
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```

**File:** rest/accountAlias.js (L10-11)
```javascript
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
const noShardRealmAccountAliasRegex = /^[A-Z2-7]+$/;
```

**File:** rest/accountAlias.js (L41-44)
```javascript
  static isValid(accountAlias, noShardRealm = false) {
    const regex = noShardRealm ? noShardRealmAccountAliasRegex : accountAliasRegex;
    return typeof accountAlias === 'string' && regex.test(accountAlias);
  }
```
