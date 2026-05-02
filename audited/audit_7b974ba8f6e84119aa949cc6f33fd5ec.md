### Title
Unauthenticated Alias Lookup Causes Unbounded Database Query Amplification via `getAccountFromAlias()`

### Summary
The REST service exposes alias-based account lookup endpoints to unauthenticated users with no rate limiting at the service layer. Each unique valid alias string submitted to endpoints like `/api/v1/accounts/:idOrAliasOrEvmAddress` triggers a direct, uncached database query via `entityFromAliasQuery`. An attacker can flood these endpoints with unique valid base32 alias strings, causing sustained database saturation that degrades or blocks legitimate mirror node query processing.

### Finding Description

**Exact code path:**

`rest/server.js` line 102 registers the endpoint publicly:
```js
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
``` [1](#0-0) 

When the path parameter matches a valid alias, `getEncodedId()` routes to `getAccountIdFromAlias()` → `getAccountFromAlias()`: [2](#0-1) 

`getAccountFromAlias()` executes a raw DB query on every call with no caching, no deduplication, and no rate limiting: [3](#0-2) 

The query itself: [4](#0-3) 

**Root cause — failed assumptions:**

1. **`authHandler` does not block unauthenticated requests.** It only sets a custom limit for authenticated users with credentials; if no credentials are provided, it simply returns and the request proceeds: [5](#0-4) 

2. **Response cache is disabled by default.** It is only active when both `config.cache.response.enabled` AND `config.redis.enabled` are true — an optional deployment configuration, not a guaranteed protection: [6](#0-5) 

3. **No rate limiting middleware exists in the REST service.** The full middleware stack (`authHandler`, `metricsHandler`, `responseCacheCheckHandler`, `responseHandler`) contains zero rate-limiting logic: [7](#0-6) 

   The throttle configuration found in the codebase (`ThrottleConfiguration.java`) belongs exclusively to the `web3` Java service and has no effect on the Node.js REST service: [8](#0-7) 

4. **Alias validation only checks format, not uniqueness.** `AccountAlias.isValid()` accepts any string matching the base32 regex `^(\d{1,5}\.){0,2}[A-Z2-7]+$`, giving an attacker an enormous space of unique valid inputs: [9](#0-8) 

### Impact Explanation

Every unique alias string bypasses any response cache (cache key is derived from the full URL including the alias value) and hits the database directly. The `entity` table query with a `WHERE alias = $1` filter on a potentially large table, executed thousands of times per second from a single or distributed attacker, saturates the PostgreSQL connection pool and I/O capacity. This prevents the mirror node's importer and other legitimate REST consumers from executing their own queries in real time, directly impairing the node's ability to serve transaction gossip and consensus data. Severity is **High** — availability impact on a public infrastructure component with no authentication barrier.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero prior knowledge beyond the public API documentation. The alias input space (base32 strings of arbitrary length) is effectively unbounded, making cache-based mitigations ineffective even if Redis is enabled. The attack is trivially scriptable with standard HTTP tooling (`ab`, `wrk`, `curl` in a loop) and is repeatable indefinitely. Any internet-accessible mirror node deployment is exposed.

### Recommendation

1. **Add a rate-limiting middleware to the REST service** (e.g., `express-rate-limit` or `rate-limiter-flexible`) applied globally before route handlers, with per-IP limits.
2. **Add an application-level cache for alias→entity-id resolution** inside `getAccountFromAlias()` or `getAccountIdFromAlias()` (e.g., an in-process LRU cache with a short TTL), so repeated lookups for the same alias do not hit the database.
3. **Do not rely solely on the optional Redis response cache** as a security control — it must be treated as a performance optimization, not a DoS mitigation.
4. **Enforce connection pool limits** at the `pg` pool level with a short `idleTimeoutMillis` and a hard `max` connection cap to bound the blast radius.

### Proof of Concept

```bash
# Generate unique valid base32 alias strings and flood the endpoint
# Requires: bash, curl, /dev/urandom

MIRROR_HOST="https://<mirror-node-host>"
API="/api/v1/accounts/"

for i in $(seq 1 10000); do
  # Generate a unique valid base32 alias (A-Z, 2-7 characters only)
  ALIAS=$(cat /dev/urandom | tr -dc 'A-Z2-7' | head -c 32)
  curl -s -o /dev/null "${MIRROR_HOST}${API}${ALIAS}" &
done
wait
```

**Preconditions:** Network access to the mirror node REST port (default 5551). No credentials required.

**Trigger:** Each request with a unique alias string passes `AccountAlias.isValid()`, enters `getAccountFromAlias()`, and executes `SELECT id FROM entity WHERE alias = $1` against the database.

**Result:** Database connection pool exhaustion; legitimate queries (transaction lookups, balance queries, gossip-related reads) begin timing out or queuing indefinitely.

### Citations

**File:** rest/server.js (L54-98)
```javascript
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
const openApiValidatorEnabled = config.openapi.validation.enabled;

app.disable('x-powered-by');
app.set('trust proxy', true);
app.set('port', port);
app.set('query parser', requestQueryParser);

serveSwaggerDocs(app);
if (openApiValidatorEnabled || isTestEnv()) {
  await openApiValidator(app);
}

// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** rest/server.js (L101-103)
```javascript
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
app.use(`${apiPrefix}/${AccountRoutes.resource}`, AccountRoutes.router);
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

**File:** rest/middleware/authHandler.js (L15-20)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }
```

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-32)
```java
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
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
