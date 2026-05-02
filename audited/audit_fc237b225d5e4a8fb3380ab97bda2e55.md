### Title
Missing Rate Limiting on GET /blocks Enables Unauthenticated DoS via Event Loop and DB Pool Exhaustion

### Summary
The Express.js REST API has no application-level rate limiting anywhere in its middleware stack, and the Traefik ingress middleware for the REST service omits the `rateLimit` and `inFlightReq` controls that are present in the Rosetta service. An unauthenticated attacker can flood `GET /api/v1/blocks` with concurrent requests, each of which issues a PostgreSQL query, exhausting the Node.js event loop queue and the database connection pool and rendering the mirror node unresponsive to all clients.

### Finding Description

**Route registration** — `rest/routes/blockRoute.js` lines 12–13 register `BlockController.getBlocks` and `BlockController.getByHashOrNumber` with no per-route middleware: [1](#0-0) 

**Global middleware stack** — `rest/server.js` lines 68–98 enumerate every middleware applied before routes: `urlencoded`, `json`, `cors`, optional `compression`, `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`. No rate-limiting middleware appears anywhere: [2](#0-1) 

**authHandler passes unauthenticated requests freely** — `rest/middleware/authHandler.js` lines 15–19: if no `Authorization` header is present, the handler returns immediately and the request proceeds. The `user.limit` field (line 32) only applies to authenticated users: [3](#0-2) 

**Each request issues a DB query** — `rest/controllers/blockController.js` line 104 calls `RecordFileService.getBlocks(formattedFilters)` unconditionally, and `rest/service/recordFileService.js` lines 149–162 execute a parameterised SQL query against PostgreSQL for every call: [4](#0-3) [5](#0-4) 

**Traefik ingress middleware for REST is missing rate controls** — `charts/hedera-mirror-rest/values.yaml` lines 134–139 define only `circuitBreaker` and `retry` for the REST service. Compare this to the Rosetta chart which adds `inFlightReq` (5 concurrent requests per IP) and `rateLimit` (10 req/s per host): [6](#0-5) 

**No rate-limit package in the REST service** — `grep` across `rest/**/*.js` for `rateLimit|rate.limit|throttle|express-rate-limit` returns only one hit in a test utility file, confirming no production rate-limiting code exists.

**The only partial control is the GCP Gateway** — `charts/hedera-mirror-rest/values.yaml` line 56 sets `maxRatePerEndpoint: 250`, but this is a per-endpoint aggregate (not per-IP), requires HPA reconfiguration to take effect, and only applies to GCP-gateway deployments: [7](#0-6) 

### Impact Explanation
Node.js is single-threaded. Thousands of concurrent requests each awaiting a PostgreSQL response saturate the event loop's microtask queue and exhaust the `pg` connection pool. Once the pool is full, new requests queue indefinitely; the process stops responding to health checks (`/health/liveness`, `/health/readiness`), causing Kubernetes to restart the pod. During the restart window all clients — including legitimate users and the internal monitor — are partitioned from the mirror node. Because the attack targets a read-only, unauthenticated endpoint, it requires no credentials, no state, and no special knowledge.

### Likelihood Explanation
Any internet-accessible deployment is reachable by a single attacker with a commodity HTTP flood tool (e.g., `wrk`, `hey`, `ab`). No authentication, no API key, no prior knowledge of the system is required. The attack is trivially repeatable and can be sustained indefinitely. The missing Traefik `inFlightReq`/`rateLimit` controls (present in the Rosetta chart but absent in the REST chart) suggest this gap was overlooked rather than intentionally accepted.

### Recommendation
1. **Application layer**: Add `express-rate-limit` (or equivalent) as a global middleware in `rest/server.js` before route registration, with a per-IP sliding-window limit (e.g., 100 req/10 s).
2. **Ingress layer**: Add `inFlightReq` and `rateLimit` entries to the `middleware` list in `charts/hedera-mirror-rest/values.yaml`, mirroring the controls already present in `charts/hedera-mirror-rosetta/values.yaml` lines 152–160.
3. **DB pool**: Set an explicit `statement_timeout` and `query_timeout` on the `pg` pool so runaway queries are cancelled rather than held open.
4. **Response cache**: Ensure `config.cache.response.enabled` and `config.redis.enabled` are on in production to absorb repeated identical queries.

### Proof of Concept
```bash
# Precondition: mirror node REST API reachable at TARGET, no credentials needed
TARGET="https://<mirror-node-host>/api/v1/blocks"

# Step 1 – flood with 500 concurrent connections, unlimited requests
wrk -t 10 -c 500 -d 60s "$TARGET"

# Step 2 – observe health endpoint becoming unresponsive
watch -n1 'curl -s -o /dev/null -w "%{http_code}" \
  https://<mirror-node-host>/health/liveness'

# Expected result: health endpoint starts returning 503 / connection refused
# within seconds; Kubernetes liveness probe fails; pod restarts;
# all clients receive connection errors during the restart window.
```

### Citations

**File:** rest/routes/blockRoute.js (L9-13)
```javascript
const router = extendExpress(express.Router());

const resource = 'blocks';
router.getExt('/', BlockController.getBlocks);
router.getExt('/:hashOrNumber', BlockController.getByHashOrNumber);
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

**File:** rest/middleware/authHandler.js (L15-35)
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
```

**File:** rest/controllers/blockController.js (L101-112)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);

    res.locals[responseDataLabel] = {
      blocks: blocks.map((model) => new BlockViewModel(model)),
      links: {
        next: this.generateNextLink(req, blocks, formattedFilters),
      },
    };
  };
```

**File:** rest/service/recordFileService.js (L149-162)
```javascript
  async getBlocks(filters) {
    const {where, params} = buildWhereSqlStatement(filters.whereQuery);

    const query =
      RecordFileService.blocksQuery +
      `
      ${where}
      order by ${filters.orderBy} ${filters.order}
      limit ${filters.limit}
    `;

    const rows = await super.getRows(query, params);
    return rows.map((recordFile) => new RecordFile(recordFile));
  }
```

**File:** charts/hedera-mirror-rest/values.yaml (L56-57)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
```

**File:** charts/hedera-mirror-rest/values.yaml (L134-140)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms

```
