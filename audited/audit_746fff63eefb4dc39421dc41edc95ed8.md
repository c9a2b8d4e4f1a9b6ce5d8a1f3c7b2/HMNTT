### Title
Missing Per-IP Rate Limiting and In-Flight Request Cap in `/api/v1/balances` Enables DB Connection Pool Exhaustion

### Summary
`getBalances()` in `rest/balances.js` issues up to three sequential DB queries per request (timestamp lookup, public-key entity lookup, main balance query) against a shared, fixed-size connection pool. The Express application has no rate-limiting or in-flight-request middleware, and the Traefik middleware that would provide those controls is both incomplete for the REST service and disabled by default (`global.middleware: false`). A sustained flood of unauthenticated requests can exhaust the pool, causing all subsequent requests to queue until `connectionTimeoutMillis` expires, effectively taking the REST API offline.

### Finding Description

**Code path — up to 3 sequential pool connections per request:**

`rest/balances.js` `getBalances()` (lines 83–156):
- Line 114: `await getTsQuery(tsQuery, tsParams)` → calls `getAccountBalanceTimestampRange()` → `pool.queryQuietly()` at line 189 of the same file.
- Line 119: `await getAccountIdsByPublicKey(pubKeyParams, limit)` → `pool.queryQuietly()` at line 66.
- Line 153: final `pool.queryQuietly(pgSqlQuery, sqlParams)`. [1](#0-0) 

**Pool is fixed-size with no overflow protection at the application layer:**

`rest/dbpool.js` configures the pool with a hard `max: config.db.pool.maxConnections` and `connectionTimeoutMillis`. Once all connections are checked out, new callers block until timeout. [2](#0-1) 

**No application-layer rate limiting in `server.js`:**

The full middleware stack registered in `server.js` is: `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`. No `express-rate-limit`, no in-flight-request cap, no per-IP throttle. [3](#0-2) 

**Traefik middleware for the REST service is missing `inFlightReq` and `rateLimit`, and is disabled by default:**

The REST chart's default middleware only contains `circuitBreaker` and `retry` (10 attempts — which amplifies load). Compare to the Rosetta chart which explicitly adds `inFlightReq: amount: 5` per IP and `rateLimit: average: 10`. More critically, `global.middleware` defaults to `false`, so even these incomplete Traefik rules are never applied in a default deployment. [4](#0-3) [5](#0-4) 

### Impact Explanation
An attacker who exhausts the DB connection pool causes every subsequent request to block for `connectionTimeoutMillis` milliseconds before returning an error. Because Node.js processes all REST routes through the same global pool, all endpoints (accounts, transactions, tokens, etc.) are simultaneously degraded — not just `/balances`. This constitutes a full REST API outage for the mirror node, which downstream clients (wallets, explorers, dApps) depend on for network state queries. The `retry: attempts: 10` Traefik rule actively worsens the situation by replaying each failed request up to 10 times, multiplying pool pressure by up to 10×.

### Likelihood Explanation
No authentication or API key is required to call `/api/v1/balances`. The timestamp filter path (`?timestamp=lte:X`) is the most expensive variant (3 DB queries). A single attacker with modest bandwidth can open hundreds of concurrent HTTP connections; because each request holds up to 3 pool slots sequentially, a pool of e.g. 10 connections is exhausted by ~4 concurrent attackers. Distributed attack (multiple IPs) trivially bypasses any IP-based controls that might be added later. The attack is fully repeatable and requires no special knowledge beyond the public OpenAPI spec. [6](#0-5) 

### Recommendation
1. **Application layer**: Add `express-rate-limit` (or equivalent) as global middleware in `server.js`, keyed on `req.ip`, before route handlers. A limit of ~50–100 req/s per IP with a short window is a reasonable starting point.
2. **Traefik middleware**: Add `inFlightReq` (e.g., `amount: 10`) and `rateLimit` to `charts/hedera-mirror-rest/values.yaml` middleware list, mirroring what the Rosetta chart already does. Set `global.middleware: true` in production overlays.
3. **Pool sizing awareness**: Expose a Prometheus alert for pool saturation (analogous to the `RestJavaHighDBConnections` rule that already exists for the Java REST service) so operators are alerted before exhaustion occurs.
4. **Reduce queries per request**: Cache the timestamp-range lookup (`getAccountBalanceTimestampRange`) with a short TTL (e.g., 15 s, matching balance snapshot granularity) to eliminate the first DB round-trip for the common case. [7](#0-6) 

### Proof of Concept
```bash
# Requires: wrk or similar HTTP load tool. No credentials needed.

# 1. Identify a valid historical timestamp (any value works; use current epoch in nanoseconds)
TS=$(date +%s)000000000

# 2. Flood /balances with timestamp filter (triggers 3 DB queries per request)
wrk -t 20 -c 500 -d 60s \
  "https://<mirror-node-host>/api/v1/balances?timestamp=lte:${TS}&limit=25"

# 3. In a separate terminal, observe legitimate requests timing out:
curl -w "%{time_total}\n" -o /dev/null -s \
  "https://<mirror-node-host>/api/v1/balances"

# Expected result after ~10-30 seconds:
# - Response times spike to connectionTimeoutMillis (default varies, often 5-30s)
# - HTTP 500 / 503 errors returned to all clients
# - Mirror node REST API fully unresponsive until attack stops
```

### Citations

**File:** rest/balances.js (L113-153)
```javascript
  if (tsQuery) {
    const tsQueryResult = await getTsQuery(tsQuery, tsParams);
    if (!tsQueryResult.query) {
      return;
    }

    const accountIdsQuery = await getAccountIdsByPublicKey(pubKeyParams, limit);
    if (pubKeyQuery && !accountIdsQuery) {
      return;
    }

    [sqlQuery, tsParams] = await getBalancesQuery(
      accountQuery,
      balanceQuery,
      accountIdsQuery,
      limitQuery,
      order,
      tsQueryResult
    );
    sqlParams = utils.mergeParams(tsParams, accountParams, balanceParams, params);
  } else {
    // use current balance from entity table when there's no timestamp query filter
    const conditions = [accountQuery, pubKeyQuery, balanceQuery].filter(Boolean).join(' and ');
    const whereClause = conditions && `where ${conditions}`;
    const tokenBalanceSubQuery = getTokenAccountBalanceSubQuery(order);
    sqlParams = utils.mergeParams(tsParams, accountParams, pubKeyParams, balanceParams, params);
    sqlQuery = `
      with entity_balance as (
        select id as account_id, balance, balance_timestamp as consensus_timestamp, public_key
        from entity
        where type in ('ACCOUNT', 'CONTRACT')
      )
      select ab.*, (${tokenBalanceSubQuery}) as token_balances
      from entity_balance ab
      ${whereClause}
      order by ab.account_id ${order}
      ${limitQuery}`;
  }

  const pgSqlQuery = utils.convertMySqlStyleQueryToPostgres(sqlQuery);
  const result = await pool.queryQuietly(pgSqlQuery, sqlParams);
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

**File:** rest/server.js (L67-98)
```javascript
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

**File:** charts/hedera-mirror-rest/values.yaml (L82-139)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
  podAnnotations: {}

hpa:
  behavior: {}
  enabled: true
  maxReplicas: 15
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80

  minReplicas: 1

image:
  pullPolicy: IfNotPresent
  pullSecrets: []
  registry: gcr.io
  repository: mirrornode/hedera-mirror-rest
  tag: ""  # Defaults to the chart's app version

ingress:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: '{{ include "hedera-mirror-rest.namespace" . }}-{{ include "hedera-mirror-rest.fullname" . }}@kubernetescrd'
  enabled: true
  hosts:
    - host: ""
      paths: ["/api/v1"]
  tls:
    enabled: false
    secretName: ""

labels: {}

livenessProbe:
  httpGet:
    path: /health/liveness
    port: http
  initialDelaySeconds: 0
  timeoutSeconds: 2

middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rest/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** rest/api/v1/openapi.yml (L391-419)
```yaml
  /api/v1/balances:
    get:
      summary: List account balances
      description:
        Returns a list of account and token balances on the network. The latest balance information is returned when
        there is no timestamp query parameter, otherwise, the information is retrieved from snapshots with 15-minute
        granularity. This information is limited to at most 50 token balances per account as outlined in HIP-367.
        As such, it's not recommended for general use and we instead recommend using either
        `/api/v1/accounts/{id}/tokens` or `/api/v1/tokens/{id}/balances` to obtain the current token balance information
        and `/api/v1/accounts/{id}` to return the current account balance.
      operationId: getBalances
      parameters:
        - $ref: "#/components/parameters/accountIdOrAliasOrEvmAddressQueryParam"
        - $ref: "#/components/parameters/accountBalanceQueryParam"
        - $ref: "#/components/parameters/accountPublicKeyQueryParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParamDesc"
        - $ref: "#/components/parameters/timestampQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/BalancesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
      tags:
        - balances
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L211-221)
```yaml
  RestJavaHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror Java REST API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="rest-java"}) by (namespace, pod) / sum(hikaricp_connections_max{application="rest-java"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: rest-java
      area: resource
      severity: critical
```
