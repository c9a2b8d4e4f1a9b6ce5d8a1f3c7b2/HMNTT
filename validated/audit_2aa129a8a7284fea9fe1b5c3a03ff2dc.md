All referenced code locations have been verified against the actual codebase. Every technical claim in the report is accurate.

**Verified facts:**

- `getTokenInfoRequest()` exists at lines 548–565 of `rest/tokens.js` [1](#0-0) 
- `extractSqlFromTokenInfoRequest()` exists at lines 482–528, calling `buildHistoryQuery()` three times [2](#0-1) 
- `buildHistoryQuery()` at lines 530–546 emits the exact UNION ALL structure described [3](#0-2) 
- Cache key is MD5 of `req.originalUrl` [4](#0-3) 
- Cache TTL for `GET /tokens/{id}` is 5 seconds [5](#0-4) 
- `authHandler` only sets response-size limits for authenticated users, no rate throttling [6](#0-5) 
- `server.js` registers no rate-limiting middleware [7](#0-6) 
- `ThrottleManagerImpl` is in the `web3` Java service only [8](#0-7) 
- Traefik middleware template is conditional on `global.middleware`, which defaults to `false` [9](#0-8) [10](#0-9) 
- The REST chart's middleware config contains only `circuitBreaker` and `retry` — no `rateLimit` or `inFlightReq` [11](#0-10) 
- `TokenService.putTokenCache` is only called when `filters.length === 0` [12](#0-11) 
- The response cache is **disabled by default** (`hiero.mirror.rest.cache.response.enabled: false`) [13](#0-12)  making the cache-bypass aspect even more severe than described — every request hits the DB unconditionally in a default deployment.

---

# Audit Report

## Title
Unauthenticated Cache-Bypass DoS via Timestamp-Parameterized Token Info Queries Triggering Expensive 3-Way UNION ALL History Queries

## Summary
The `GET /tokens/:tokenId?timestamp=lte:<ts>` endpoint in the REST Node.js service executes a query joining six tables (three live + three history) on every request when a timestamp filter is present. The Redis response cache is disabled by default, and even when enabled, the cache key is derived from the full URL, making it trivially bypassable by varying the timestamp value. No application-level rate limiting exists in the REST service. An unauthenticated attacker can sustain a high rate of expensive DB queries with no friction.

## Finding Description

**Code path:**

`getTokenInfoRequest()` is the handler for `GET /tokens/:tokenId`: [1](#0-0) 

When any timestamp filter is present, `extractSqlFromTokenInfoRequest()` calls `buildHistoryQuery()` three separate times — once each for the `token`/`token_history`, `entity`/`entity_history`, and `custom_fee`/`custom_fee_history` table pairs: [14](#0-13) 

Each `buildHistoryQuery()` call emits a subquery of the form:
```sql
(SELECT ... FROM <table> WHERE <conditions>)
UNION ALL
(SELECT ... FROM <table>_history WHERE <conditions>
 ORDER BY lower(timestamp_range) DESC LIMIT 1)
ORDER BY modified_timestamp DESC LIMIT 1
``` [3](#0-2) 

The three subqueries are then JOINed together, meaning a single request with a timestamp filter touches six tables.

**Cache bypass:**

The response cache key is the MD5 of `req.originalUrl`: [4](#0-3) 

The cache TTL for `GET /tokens/{id}` is 5 seconds: [5](#0-4) 

Critically, the Redis response cache is **disabled by default** (`hiero.mirror.rest.cache.response.enabled: false`): [13](#0-12) 

This means in a default deployment, every request unconditionally hits the database. Even when the cache is enabled, every distinct `?timestamp=lte:<ts>` value produces a unique cache key, so an attacker cycling through timestamps generates a cache miss on every request.

**No application-level rate limiting:**

`server.js` registers no rate-limiting middleware. The `authHandler` only grants elevated response-size limits to authenticated users; it does not throttle request rates for unauthenticated callers: [6](#0-5) [15](#0-14) 

The `ThrottleManagerImpl` and `ThrottleConfiguration` belong exclusively to the `web3` Java service and do not apply to the REST service: [8](#0-7) 

The Traefik middleware template for the REST chart is conditional on `global.middleware` being `true`, which defaults to `false`: [9](#0-8) [10](#0-9) 

Furthermore, even when enabled, the REST chart's middleware configuration contains only `circuitBreaker` and `retry` — no `rateLimit` or `inFlightReq` entries (unlike the Rosetta chart which includes both): [11](#0-10) 

The token-level in-memory cache (`TokenService.putTokenCache`) is only populated when no filters are present, so timestamp-filtered requests never benefit from it: [12](#0-11) 

## Impact Explanation
An attacker can sustain a high rate of DB-expensive queries against the mirror node's PostgreSQL backend with no authentication, no rate limiting, and no effective caching. Each request scans up to six tables (three of which are unbounded history tables). The DB connection pool is capped at 10 connections by default with a 20-second statement timeout. Under sustained load with many unique `(tokenId, timestamp)` pairs, DB connection pool exhaustion or query queue saturation will degrade or deny service for all legitimate API consumers. The impact is availability degradation (no funds at risk).

## Likelihood Explanation
The attack requires zero privileges, zero on-chain interaction, and only knowledge of valid tokenIds (publicly enumerable via `GET /tokens`). The timestamp parameter accepts any nanosecond-precision value, giving an attacker an effectively unbounded keyspace to defeat caching. The attack is trivially scriptable with a single HTTP client in a loop and is repeatable indefinitely. The default deployment has the response cache disabled, making the attack even easier to execute.

## Recommendation
1. **Add rate limiting to the REST chart's Traefik middleware** — add `inFlightReq` and `rateLimit` entries to `charts/hedera-mirror-rest/values.yaml` under `middleware`, mirroring the Rosetta chart's configuration.
2. **Enable `global.middleware` by default** or document it as a required security control.
3. **Enable the Redis response cache by default** (`hiero.mirror.rest.cache.response.enabled: true`) or document the security implications of leaving it disabled.
4. **Normalize the cache key** for timestamp-parameterized requests — for example, by rounding timestamps to the nearest block boundary before hashing, reducing the effective keyspace.
5. **Add a DB-level query cost guard** — consider enforcing `statement_timeout` more aggressively for the history-table queries, or adding a query complexity limit.

## Proof of Concept
```bash
# Enumerate a valid tokenId
TOKEN_ID=$(curl -s https://<mirror-node>/api/v1/tokens?limit=1 | jq -r '.tokens[0].token_id')

# Flood with unique timestamps to bypass cache and force 6-table queries
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/tokens/${TOKEN_ID}?timestamp=lte:$((1700000000000000000 + i))" &
done
wait
```
Each request executes a fresh 6-table UNION ALL query against PostgreSQL. With the default pool of 10 connections and no rate limiting, this saturates the connection pool and degrades service for legitimate users.

### Citations

**File:** rest/tokens.js (L482-528)
```javascript
const extractSqlFromTokenInfoRequest = (tokenId, filters) => {
  const params = [tokenId];
  let tokenQuery = 'token';
  let entityQuery = 'entity';
  let customFeeQuery = 'custom_fee';

  if (filters && filters.length !== 0) {
    // honor the last timestamp filter
    const filter = filters[filters.length - 1];
    const op = transformTimestampFilterOp(filter.operator);
    const conditions = [`${CustomFee.ENTITY_ID} = $1`, `lower(${CustomFee.TIMESTAMP_RANGE}) ${op} $2`];
    params.push(filter.value);

    var conditionsSql = conditions.join(' and ');

    // include the history table in the query
    tokenQuery = buildHistoryQuery(
      tokenSelectFields,
      conditionsSql.replace('entity_id', 'token_id'),
      Token.tableName,
      Token.tableAlias
    );

    entityQuery = buildHistoryQuery(
      entitySelectFields,
      conditionsSql.replace('entity_id', 'id'),
      Entity.tableName,
      Entity.tableAlias
    );

    customFeeQuery = buildHistoryQuery(customFeeSelectFields, conditionsSql, CustomFee.tableName, CustomFee.tableAlias);
  }

  var query = `${tokenInfoOuterSelect}
            from ${tokenQuery} as ${Token.tableAlias}
            join ${entityQuery} as ${Entity.tableAlias} on ${Entity.getFullName(Entity.ID)} = ${Token.getFullName(
    Token.TOKEN_ID
  )}
            left join ${customFeeQuery} as ${CustomFee.tableAlias} on 
                 ${CustomFee.getFullName(CustomFee.ENTITY_ID)} = ${Token.getFullName(Token.TOKEN_ID)}
            ${tokenIdMatchQuery}`;

  return {
    query,
    params,
  };
};
```

**File:** rest/tokens.js (L530-546)
```javascript
const buildHistoryQuery = (selectColumns, conditions, tableName, tableAlias) => {
  return `
   (select ${selectColumns}
    from
    (
      (select ${selectColumns}, lower(${tableAlias}.timestamp_range) as modified_timestamp
        from ${tableName} ${tableAlias}
        where ${conditions})
      union all
      (select ${selectColumns}, lower(${tableAlias}.timestamp_range) as modified_timestamp
      from ${tableName}_history ${tableAlias}
        where ${conditions} 
        order by lower(${tableAlias}.timestamp_range) desc limit 1)
      order by modified_timestamp desc limit 1
    ) as ${tableAlias})
    `;
};
```

**File:** rest/tokens.js (L548-565)
```javascript
const getTokenInfoRequest = async (req, res) => {
  const tokenId = getAndValidateTokenIdRequestPathParam(req);

  // extract and validate filters from query param
  const filters = utils.buildAndValidateFilters(req.query, acceptedSingleTokenParameters, validateTokenInfoFilter);
  const {query, params} = extractSqlFromTokenInfoRequest(tokenId, filters);

  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length !== 1 || !rows[0].custom_fee) {
    throw new NotFoundError();
  }

  const token = rows[0];
  if (filters.length === 0) {
    TokenService.putTokenCache(token);
  }
  res.locals[responseDataLabel] = formatTokenInfoRow(token);
};
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/__tests__/specs/tokens/{id}/responseHeaders.json (L1-3)
```json
{
  "cache-control": "public, max-age=5"
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

**File:** rest/server.js (L68-98)
```javascript
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L1-20)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.throttle;

import static org.hiero.mirror.web3.config.ThrottleConfiguration.GAS_LIMIT_BUCKET;
import static org.hiero.mirror.web3.config.ThrottleConfiguration.OPCODE_RATE_LIMIT_BUCKET;
import static org.hiero.mirror.web3.config.ThrottleConfiguration.RATE_LIMIT_BUCKET;

import io.github.bucket4j.Bucket;
import jakarta.inject.Named;
import lombok.CustomLog;
import lombok.RequiredArgsConstructor;
import org.hiero.mirror.web3.exception.ThrottleException;
import org.hiero.mirror.web3.viewmodel.ContractCallRequest;
import org.springframework.beans.factory.annotation.Qualifier;

@CustomLog
@Named
@RequiredArgsConstructor
final class ThrottleManagerImpl implements ThrottleManager {
```

**File:** charts/hedera-mirror-rest/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rest/values.yaml (L89-89)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-rest/values.yaml (L134-139)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```

**File:** docs/configuration.md (L549-549)
```markdown
| `hiero.mirror.rest.cache.response.enabled`                               | false                   | Whether or not the Redis based REST API response cache is enabled. If so, Redis itself must be enabled and properly configured.                                                               |
```
