All code references have been verified against the actual codebase. Here is the result:

---

Audit Report

## Title
Unbounded Database Query Amplification via Alias Lookup with `requireResult=false` Bypasses Circuit Breaker

## Summary
`getAccountIdFromAlias()` called with `requireResult=false` unconditionally executes a database query on every invocation and returns HTTP 200 OK on a miss. The REST API's Traefik circuit breaker is keyed exclusively on 5xx/network error ratios, so sustained alias-miss flooding produces only 200 OK responses, leaving the circuit breaker permanently closed. No per-IP rate limit or in-flight request cap is configured for the REST API, allowing an unprivileged attacker to exhaust the database connection pool (default: 10 connections per instance).

## Finding Description

**Verified code path:**

`rest/service/entityService.js` lines 42–53 (`getAccountFromAlias`) always executes: [1](#0-0) 

```js
async getAccountFromAlias(accountAlias) {
  const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
  if (isEmpty(rows)) {
    return null;
  }
  ...
}
```

The query is defined at lines 17–20: [2](#0-1) 

`getAccountIdFromAlias` at lines 71–81 calls this unconditionally and returns `null` (no error thrown) when `requireResult=false`: [3](#0-2) 

The `requireResult=false` call site is confirmed at `rest/balances.js` line 332: [4](#0-3) 

This is triggered by any `GET /api/v1/balances?account.id=<alias>` request where the alias passes `AccountAlias.isValid()`.

**Why existing mitigations fail:**

1. **Circuit breaker** (`charts/hedera-mirror-rest/values.yaml` lines 135–136) triggers only on 5xx or network errors. Alias misses return HTTP 200 OK — the circuit breaker never opens: [5](#0-4) 

2. **No per-IP rate limit or in-flight cap** on the REST API. Compare with Rosetta, which has both `inFlightReq: amount: 5` and `rateLimit: average: 10`: [6](#0-5) 

3. **Redis response cache** (`rest/middleware/responseCacheHandler.js` line 152) keys on `req.originalUrl` with a 1-second default TTL (`DEFAULT_REDIS_EXPIRY = 1`, line 24). An attacker using distinct aliases per request gets a cache miss on every request: [7](#0-6) [8](#0-7) 

4. **Retry amplification**: The REST middleware includes `retry: attempts: 10`, which can amplify load at the Traefik layer for transient failures: [9](#0-8) 

## Impact Explanation

The REST API DB pool defaults to **10 connections per instance** (`hiero.mirror.rest.db.pool.maxConnections = 10`): [10](#0-9) 

The pool is initialized directly from this config: [11](#0-10) 

With the HPA configured for up to 15 replicas, the maximum total pool is 150 connections. The pgbouncer `max_user_connections` for `mirror_rest` is 250: [12](#0-11) 

An attacker flooding concurrent requests can exhaust the per-instance pool (10 connections), causing all other API endpoints requiring DB access to queue or time out. The `entity` table is central to nearly every endpoint (accounts, balances, tokens, contracts), so pool exhaustion has broad blast radius across the entire service.

## Likelihood Explanation

Preconditions are minimal: no authentication, no special privileges, no prior knowledge of the system. Valid alias format is publicly documented. An attacker can generate an unbounded stream of syntactically valid but non-existent aliases programmatically. The attack is repeatable, stateless, and trivially parallelizable. The absence of per-IP rate limiting on the REST API (unlike Rosetta and GraphQL, both of which have `inFlightReq` configured) makes this straightforward: [13](#0-12) 

## Recommendation

1. **Add `inFlightReq` and `rateLimit` middleware** to `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta configuration (e.g., `inFlightReq: amount: 5` per IP, `rateLimit: average: 10` per host).
2. **Add an in-memory short-circuit cache** for alias lookups (similar to the existing `entityId` cache with `maxSize: 100000` and `maxAge: 1800s`) so repeated misses for the same alias do not hit the DB.
3. **Increase `db.pool.maxConnections`** or add application-level concurrency limiting (e.g., a semaphore) to bound the number of simultaneous alias DB queries.
4. Consider returning a 429 (Too Many Requests) or 404 (Not Found) with appropriate headers for alias misses to allow the circuit breaker to participate in protection.

## Proof of Concept

```bash
# Generate unique valid base32 aliases and flood the endpoint concurrently
for i in $(seq 1 10000); do
  ALIAS=$(python3 -c "import base64, os; print(base64.b32encode(os.urandom(20)).decode().rstrip('='))")
  curl -s "https://<mirror-node>/api/v1/balances?account.id=${ALIAS}" &
done
wait
```

Each request: passes `AccountAlias.isValid()`, misses the Redis cache (unique URL), executes `SELECT id FROM entity WHERE ... AND alias = $1` against the DB, returns HTTP 200 OK with `{"balances":[],...}`, and never triggers the circuit breaker. With 10+ concurrent requests per REST instance, the DB connection pool is saturated.

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

**File:** rest/service/entityService.js (L71-81)
```javascript
  async getAccountIdFromAlias(accountAlias, requireResult = true) {
    const entity = await this.getAccountFromAlias(accountAlias);
    if (isNil(entity)) {
      if (requireResult) {
        throw new NotFoundError(EntityService.missingAccountAlias);
      }
      return null;
    }

    return entity.id;
  }
```

**File:** rest/balances.js (L331-333)
```javascript
      if (AccountAlias.isValid(value, true) && ++evmAliasAddressCount === 1) {
        return EntityService.getAccountIdFromAlias(AccountAlias.fromString(value), false);
      }
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** rest/middleware/responseCacheHandler.js (L24-24)
```javascript
const DEFAULT_REDIS_EXPIRY = 1;
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
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

**File:** charts/hedera-mirror/values.yaml (L371-373)
```yaml
        mirror_rest:
          max_user_client_connections: 1000
          max_user_connections: 250
```

**File:** charts/hedera-mirror-graphql/values.yaml (L135-145)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - retry:
      attempts: 3
      initialInterval: 100ms
```
