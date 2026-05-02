### Title
Unauthenticated Per-Request DB Query via `block.hash` Filter on `GET /contracts/results` Enables Griefing DoS

### Summary
Any unauthenticated caller can send `GET /api/v1/contracts/results?block.hash=<hash>` and cause `extractContractResultsByIdQuery()` to unconditionally issue a secondary `SELECT … FROM record_file WHERE hash LIKE $1` query on every request. The REST API has no rate limiting, and the optional response cache is disabled by default and bypassed by varying the hash value. A flood of such requests exhausts the DB connection pool and degrades the record-file service for all users.

### Finding Description

**Code path:**

1. `GET /api/v1/contracts/results` is handled by `getContractResults()`. [1](#0-0) 

2. It calls `extractContractResultsByIdQuery(filters)` with no contractId. [2](#0-1) 

3. Inside `extractContractResultsByIdQuery`, when `blockFilter.key === filterKeys.BLOCK_HASH`, the code unconditionally awaits a DB call: [3](#0-2) 

4. `getRecordFileBlockDetailsFromHash()` executes a `LIKE`-based SQL query against the `record_file` table on every invocation — no caching, no memoization: [4](#0-3) [5](#0-4) 

**Root cause:** The function assumes `block.hash` lookups are infrequent or protected upstream. Neither assumption holds.

**Why existing checks fail:**

- The response cache (`responseCacheCheckHandler`) is gated on `config.cache.response.enabled && config.redis.enabled`, which is **disabled by default**. Even when enabled, the cache key is the full URL MD5, so each distinct hash value is a cache miss. [6](#0-5) [7](#0-6) 

- The REST server has **no rate-limiting middleware** for `GET /contracts/results`. The throttle logic found in the codebase (`ThrottleManagerImpl`, `ThrottleConfiguration`) belongs exclusively to the `web3` Java service for `POST /contracts/call` — it is not applied to the Node.js REST API. [8](#0-7) 

- `authHandler` is present but the endpoint is public; no authentication is required. [9](#0-8) 

### Impact Explanation
Each request with a `block.hash` filter consumes one DB connection for the `record_file` lookup, plus a second connection for the main `contract_result` query. A sustained flood from a single IP exhausts the PostgreSQL connection pool, causing timeouts and errors for all concurrent users of the mirror node REST API. The `record_file` table is shared across block, contract-result, and other endpoints, so degradation is cross-cutting. Severity is medium: no funds are at risk, but availability of the public API is compromised.

### Likelihood Explanation
The endpoint is unauthenticated and publicly documented in the OpenAPI spec. An attacker needs only a list of valid block hashes (trivially obtained from `GET /api/v1/blocks`) and a basic HTTP flood tool. No special privileges, tokens, or on-chain interaction are required. The attack is repeatable and cheap to sustain.

### Recommendation
1. **Add rate limiting** to the REST API (e.g., `express-rate-limit` per IP) specifically for endpoints that trigger secondary DB lookups.
2. **Cache `getRecordFileBlockDetailsFromHash` results** at the service layer (e.g., an in-process LRU cache keyed on the hash prefix), since block hashes are immutable once written.
3. **Require the response cache** (Redis) to be enabled in production deployments, and document this as a security requirement.
4. As a short-term mitigation, enforce a minimum hash prefix length before issuing the `LIKE` query to prevent trivially short wildcard scans.

### Proof of Concept
```bash
# 1. Obtain a valid block hash
HASH=$(curl -s https://<mirror-node>/api/v1/blocks?limit=1 | jq -r '.blocks[0].hash')

# 2. Flood the endpoint with that hash (or rotate through known hashes)
for i in $(seq 1 5000); do
  curl -s "https://<mirror-node>/api/v1/contracts/results?block.hash=${HASH}" &
done
wait

# 3. Observe: DB connection pool exhaustion, increased query latency,
#    503/timeout errors on unrelated endpoints (e.g., /api/v1/blocks)
```

Each iteration triggers one `SELECT … FROM record_file WHERE hash LIKE $1 LIMIT 1` query with no server-side throttle or cache protecting it.

### Citations

**File:** rest/controllers/contractController.js (L486-492)
```javascript
    if (blockFilter) {
      let blockData;
      if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
      } else {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
      }
```

**File:** rest/controllers/contractController.js (L1050-1067)
```javascript
  getContractResults = async (req, res) => {
    const filters = utils.buildAndValidateFilters(
      req.query,
      acceptedContractResultsParameters,
      contractResultsFilterValidityChecks
    );

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);

    const response = {
      results: [],
      links: {
        next: null,
      },
    };
    res.locals[responseDataLabel] = response;
    const {conditions, params, order, limit, skip, next} = await this.extractContractResultsByIdQuery(filters);
```

**File:** rest/service/recordFileService.js (L58-62)
```javascript
  static recordFileBlockDetailsFromHashQuery = `select
    ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.HASH}, ${RecordFile.INDEX}
    from ${RecordFile.tableName}
    where  ${RecordFile.HASH} like $1
    limit 1`;
```

**File:** rest/service/recordFileService.js (L143-147)
```javascript
  async getRecordFileBlockDetailsFromHash(hash) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromHashQuery, [`${hash}%`]);

    return row === null ? null : new RecordFile(row);
  }
```

**File:** rest/server.js (L54-54)
```javascript
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
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

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
