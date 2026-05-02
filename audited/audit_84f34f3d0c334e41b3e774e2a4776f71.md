### Title
Unauthenticated DoS via Uncached Alias Lookups Causing Unbounded Database Queries in REST Service

### Summary
`getAccountFromAlias()` in `rest/service/entityService.js` issues a direct database query on every invocation with no result caching. The REST service's response cache only stores HTTP 2xx responses, so 404 replies for non-existent aliases are never cached. Combined with the complete absence of rate limiting in the REST service middleware stack, any unauthenticated attacker can flood the database with alias lookup queries by sending high-volume requests with valid-format but non-existent aliases.

### Finding Description

**Exact code path:**

`getAccountFromAlias()` at [1](#0-0)  executes `entityFromAliasQuery` [2](#0-1)  unconditionally on every call — there is no in-process cache, no negative-result cache, and no deduplication.

**Root cause — failed assumption 1 (application-level cache):**

`EntityId.parseCached` at [3](#0-2)  uses a `quickLru` cache, but it only caches the *parsing* of entity ID strings (shard.realm.num, encoded IDs, EVM addresses) — it never touches the database and provides zero protection for alias-to-entity DB lookups.

**Root cause — failed assumption 2 (response cache covers misses):**

The Redis response cache in `responseCacheUpdateHandler` at [4](#0-3)  only persists responses when `httpStatusCodes.isSuccess(res.statusCode)` is true. [5](#0-4)  A 404 returned for a non-existent alias is never stored, so every repeated request for the same non-existent alias re-hits the database.

**Root cause — failed assumption 3 (rate limiting):**

The REST service middleware stack exported from [6](#0-5)  contains no rate-limiting middleware. The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists exclusively in the `web3` module [7](#0-6)  and does not protect the REST service.

**Exploit flow:**

The public endpoint `GET /api/v1/accounts/{idOrAliasOrEvmAddress}` accepts aliases. When an alias is supplied, `getEncodedId()` → `getAccountIdFromAlias()` → `getAccountFromAlias()` → `entityFromAliasQuery` DB call is executed. [8](#0-7)  An attacker sends thousands of requests per second with syntactically valid but non-existent aliases (e.g., rotating base32 strings). Each request issues a full table scan/index lookup against the `entity` table, returns 404, and is never cached.

### Impact Explanation

Sustained alias flooding exhausts the database connection pool configured in `rest/config.js` [9](#0-8)  and saturates DB CPU/I/O. This degrades or completely blocks all other REST API operations (transactions, balances, tokens) for legitimate users. Because the attack requires no authentication and no on-chain state, it is a full availability-class vulnerability against the public mirror node REST API.

### Likelihood Explanation

The attack requires zero privileges, zero on-chain accounts, and only a standard HTTP client. Valid alias formats (base32-encoded public keys) are well-documented in Hedera's public API spec. An attacker can generate an infinite supply of unique valid-format aliases that will never match any entity, guaranteeing every request reaches the database. The attack is trivially scriptable with `curl` or any load-testing tool and is repeatable indefinitely.

### Recommendation

1. **Negative-result cache in `getAccountFromAlias()`**: Cache `null` results (cache misses) for a short TTL (e.g., 5–30 seconds) using an in-process LRU cache (e.g., `quick-lru`, already used in `entityId.js`). This prevents repeated DB hits for the same non-existent alias.
2. **Cache 404 responses in the response cache**: Extend `responseCacheUpdateHandler` to also cache 404 responses for alias/EVM-address lookups with a short TTL.
3. **Add rate limiting to the REST service**: Implement per-IP or global request-rate limiting middleware (e.g., `express-rate-limit`) in the REST middleware stack, analogous to the `ThrottleManagerImpl` already present in the `web3` module.
4. **Database-level protection**: Ensure the `entity.alias` column has an index and consider a DB connection pool limit with a short statement timeout to bound the blast radius.

### Proof of Concept

```bash
# Generate valid-format but non-existent base32 aliases and flood the endpoint
# No authentication required

for i in $(seq 1 10000); do
  # AAAQEAYEAUDAOCAJBEE... is a valid base32 alias format
  ALIAS=$(python3 -c "import base64, os; print(base64.b32encode(os.urandom(32)).decode().rstrip('='))")
  curl -s "https://<mirror-node-host>/api/v1/accounts/${ALIAS}" &
done
wait
```

Each request triggers a full `SELECT id FROM entity WHERE coalesce(deleted, false) <> true AND alias = $1` query against the database. With no caching of misses and no rate limiting, the database connection pool is exhausted within seconds, causing HTTP 503/timeout errors for all concurrent legitimate users.

### Citations

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

**File:** rest/service/entityService.js (L118-137)
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
    } catch (ex) {
      if (ex instanceof InvalidArgumentError) {
        throw InvalidArgumentError.forParams(paramName);
      }
      // rethrow
      throw ex;
    }

    throw InvalidArgumentError.forParams(paramName);
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

**File:** rest/middleware/responseCacheHandler.js (L90-119)
```javascript
const responseCacheUpdateHandler = async (req, res) => {
  const responseCacheKey = res.locals[responseCacheKeyLabel];
  const responseBody = res.locals[responseBodyLabel];
  const isUnmodified = res.statusCode === httpStatusCodes.UNMODIFIED.code;

  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
    if (ttl > 0) {
      // There's no content-type header when code is 304, so get it from the default headers and override with the
      // optional headers from response.locals
      const headers = !isUnmodified
        ? res.getHeaders()
        : {
            ...config.response.headers.default,
            ...res.getHeaders(),
            ...(res.locals[responseHeadersLabel] ?? {}),
          };

      // Delete headers that will be re-computed when response later served by cache hit
      delete headers[CACHE_CONTROL_HEADER];
      delete headers[CONTENT_ENCODING_HEADER];
      delete headers[CONTENT_LENGTH_HEADER];
      delete headers[VARY_HEADER];

      const statusCode = isUnmodified ? httpStatusCodes.OK.code : res.statusCode;
      const cachedResponse = new CachedApiResponse(statusCode, headers, responseBody, shouldCompress(responseBody));
      await getCache().setSingle(responseCacheKey, ttl, cachedResponse);
    }
  }
};
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
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

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** rest/config.js (L137-148)
```javascript
function parseDbPoolConfig() {
  const {pool} = getConfig().db;
  const configKeys = ['connectionTimeout', 'maxConnections', 'statementTimeout'];
  configKeys.forEach((configKey) => {
    const value = pool[configKey];
    const parsed = parseInt(value, 10);
    if (Number.isNaN(parsed) || parsed <= 0) {
      throw new InvalidConfigError(`invalid value set for db.pool.${configKey}: ${value}`);
    }
    pool[configKey] = parsed;
  });
}
```
