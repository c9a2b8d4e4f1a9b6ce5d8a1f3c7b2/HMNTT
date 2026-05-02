### Title
Unauthenticated Connection Pool Exhaustion via Unbounded EVM Address Lookup Requests

### Summary
The REST API's `getEntityIdFromEvmAddress()` function in `rest/service/entityService.js` issues a database query for every EVM address lookup with no per-request rate limiting or concurrency control for unauthenticated callers. Because the underlying `pg` connection pool has a finite `maxConnections` ceiling and the REST middleware stack contains no throttling layer, a flood of concurrent unauthenticated requests can hold all pool slots simultaneously, starving legitimate traffic of database connections.

### Finding Description
**Exact code path:**

`getEntityIdFromEvmAddress()` (line 91) calls `this.getRows(EntityService.entityFromEvmAddressQuery, [...])`. [1](#0-0) 

`BaseService.getRows()` (line 56) delegates directly to `this.pool().queryQuietly(query, params)`, acquiring a connection from the global pool for the lifetime of the query. [2](#0-1) 

The pool is initialised in `dbpool.js` with a hard ceiling of `config.db.pool.maxConnections` connections and a `connectionTimeoutMillis` after which waiting callers receive an error. [3](#0-2) 

**REST middleware stack — no rate limiting:**

The entire REST middleware export list is: `authHandler`, `handleError`, `openApiValidator`, `serveSwaggerDocs`, request/response handlers, and a response cache handler. [4](#0-3) 

`authHandler` only sets a custom response-row *limit* for authenticated users; it does not throttle or reject unauthenticated requests. [5](#0-4) 

`requestHandler.js` performs query-string parsing and request logging only — no concurrency or rate controls. [6](#0-5) 

**Contrast with web3:** The `web3` module has a full `ThrottleConfiguration` / `ThrottleManagerImpl` with per-second request and gas-limit buckets. [7](#0-6) 

The REST API has no equivalent.

**Root cause:** The REST API assumes an upstream reverse proxy or infrastructure layer enforces rate limits. No such enforcement is present in the application code itself. Every unauthenticated HTTP request that resolves to an EVM address path unconditionally acquires a pool connection.

### Impact Explanation
When all `maxConnections` slots are occupied, `pg` queues subsequent `pool.query()` calls in memory. After `connectionTimeoutMillis` elapses, those calls reject with a connection-timeout error, which propagates as a 500 to the caller. During the saturation window every legitimate API consumer — account lookups, transaction queries, contract queries — that requires a database connection is either delayed or fails. This constitutes a full application-layer DoS of the mirror-node REST API without any network-layer amplification.

### Likelihood Explanation
No authentication, API key, or proof-of-work is required. A single attacker with a modest HTTP client (e.g., `wrk`, `hey`, or a simple async script) can open hundreds of concurrent connections. The `entityFromEvmAddressQuery` is a simple indexed SELECT, so each query completes quickly — but at high enough concurrency the pool remains saturated continuously. The attack is trivially repeatable and scriptable, requires no special knowledge of the system beyond the public API surface, and is effective against any deployment that has not added an external rate-limiting proxy. [8](#0-7) 

### Recommendation
1. **Add application-level rate limiting to the REST API.** Introduce a middleware (e.g., `express-rate-limit` or a token-bucket equivalent mirroring the web3 `ThrottleConfiguration`) that caps requests per IP per second before any database work is attempted.
2. **Cap pool wait-queue depth.** Configure `pg`'s `maxWaitingClients` (or equivalent) so that the in-memory queue does not grow unboundedly under flood conditions.
3. **Add a query-level circuit breaker.** Reject new requests with HTTP 429 when the number of in-flight pool queries exceeds a configurable threshold.
4. **Document the external proxy requirement.** If rate limiting is intentionally delegated to an ingress layer (e.g., Traefik middleware as seen in `charts/hedera-mirror-rest-java/templates/middleware.yaml`), enforce its presence and document the minimum required configuration. [9](#0-8) 

### Proof of Concept
```bash
# Precondition: REST API accessible at $HOST, no upstream rate limiter
# Step 1 – generate 200 concurrent EVM address lookup requests in a tight loop
wrk -t8 -c200 -d30s \
  "http://$HOST/api/v1/accounts/0x000000000000000000000000000000000000abcd"

# Step 2 – in a separate terminal, issue a legitimate request
curl -v "http://$HOST/api/v1/accounts/0.0.1"

# Expected result during the flood:
# - curl receives HTTP 500 or hangs until connectionTimeoutMillis expires
# - wrk output shows non-zero socket/read errors once pool is saturated
# - Application logs show repeated "connection timeout" errors from pg pool
```

The attack requires no credentials, no special headers, and no knowledge beyond the public API path. Any valid or invalid 20-byte hex string triggers the full `entityFromEvmAddressQuery` execution path. [10](#0-9)

### Citations

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
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

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
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

**File:** rest/middleware/requestHandler.js (L22-29)
```javascript
const requestLogger = async (req, res) => {
  const requestId = await randomString(8);
  httpContext.set(requestIdLabel, requestId);

  // set default http OK code for reference
  res.locals.statusCode = httpStatusCodes.OK.code;
  res.locals[requestStartTime] = Date.now();
};
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
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

**File:** charts/hedera-mirror-rest-java/templates/middleware.yaml (L1-28)
```yaml
# SPDX-License-Identifier: Apache-2.0

{{ if and .Values.global.middleware .Values.middleware -}}
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  labels: {{ include "hedera-mirror-rest-java.labels" . | nindent 4 }}
  name: {{ include "hedera-mirror-rest-java.fullname" . }}
  namespace: {{ include "hedera-mirror-rest-java.namespace" . }}
spec:
  chain:
    middlewares:
{{- range .Values.middleware }}
      - name: {{ include "hedera-mirror-rest-java.fullname" $ }}-{{ keys . | first | kebabcase }}
{{- end }}

{{- range .Values.middleware }}
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  labels: {{ include "hedera-mirror-rest-java.labels" $ | nindent 4 }}
  name: {{ include "hedera-mirror-rest-java.fullname" $ }}-{{ keys . | first | kebabcase }}
  namespace: {{ include "hedera-mirror-rest-java.namespace" $ }}
spec:
  {{- . | toYaml | nindent 2 }}
{{- end }}
{{- end }}
```
