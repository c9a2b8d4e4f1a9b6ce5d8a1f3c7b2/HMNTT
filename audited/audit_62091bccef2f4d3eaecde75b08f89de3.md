### Title
Unauthenticated `block_hash` Filter Causes Unbounded DB Connection Pool Exhaustion via Concurrent Hash Lookups

### Summary
The `extractContractResultsByIdQuery()` function in `rest/controllers/contractController.js` unconditionally issues a database query for every request that supplies a `block_hash` filter, with no rate limiting on the REST API layer. Because the DB connection pool defaults to only 10 connections and no per-IP or global request throttle exists for the Node.js REST service, an unprivileged attacker sending many concurrent requests with different non-existent hashes can hold all pool connections simultaneously, denying service to legitimate users.

### Finding Description

**Exact code path:**

In `rest/controllers/contractController.js` lines 486–501, when a `blockFilter` with key `BLOCK_HASH` is present, the code unconditionally awaits a DB query:

```js
// contractController.js lines 486-501
if (blockFilter) {
  let blockData;
  if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
    blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
  } else {
    blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
  }
  ...
}
``` [1](#0-0) 

`getRecordFileBlockDetailsFromHash` in `rest/service/recordFileService.js` executes:

```sql
SELECT consensus_start, consensus_end, hash, index
FROM record_file
WHERE hash LIKE $1   -- $1 = '<attacker_hash>%'
LIMIT 1
``` [2](#0-1) 

The parameter is constructed as `` `${hash}%` `` (line 144), a prefix-LIKE pattern: [3](#0-2) 

**Root cause — no rate limiting on the REST API:**

A search of `rest/**/*.js` for any rate-limiting middleware returns zero results in production code. The throttling that exists (`ThrottleConfiguration`, `ThrottleManagerImpl`) is exclusively in the `web3` Java service and does not apply to the Node.js REST API: [4](#0-3) 

The REST server middleware chain (`rest/server.js`) includes only `cors`, `compression`, `requestLogger`, `authHandler` (metrics auth), and optional Redis response cache — no rate limiter: [5](#0-4) 

**DB pool size:**

The default pool is capped at **10 connections** (`maxConnections: 10`) with a `connectionTimeout` of 20 000 ms and `statementTimeout` of 20 000 ms: [6](#0-5) [7](#0-6) 

**Exploit flow:**

1. Attacker sends ≥10 concurrent HTTP requests to the public endpoint:
   `GET /api/v1/contracts/0.0.1234/results?block.hash=<unique_random_32-byte_hex>`
2. `contractResultsFilterValidityChecks` passes the hash through standard format validation only — no operator restriction for `BLOCK_HASH` (only `BLOCK_NUMBER` gets the `eq`-only check): [8](#0-7) 
3. Each request reaches `getRecordFileBlockDetailsFromHash`, acquires a pool connection, and executes the LIKE query. For non-existent hashes the query must scan (or index-scan) and return null — holding the connection for the query duration.
4. With all 10 connections occupied, the 11th legitimate request blocks for up to 20 s waiting for a connection, then times out.
5. Repeating at a modest rate (e.g., 50 req/s) keeps the pool perpetually saturated.

### Impact Explanation

All REST API endpoints that share the same `pg` pool are affected, not just the contract-results endpoint. Legitimate users receive connection-timeout errors (HTTP 500 / 503) for the duration of the attack. The default pool of 10 connections means the threshold for full denial of service is extremely low. The `statementTimeout` of 20 s means each held connection blocks the pool for up to 20 s per request, amplifying the effect.

### Likelihood Explanation

No authentication is required. The `block_hash` query parameter is documented and publicly accessible. The attack requires only a standard HTTP client capable of sending concurrent requests — trivially scripted with `curl --parallel`, `ab`, `wrk`, or any async HTTP library. The attacker does not need to know any valid contract ID; any syntactically valid entity ID (e.g., `0.0.1`) combined with random hex hashes suffices. The attack is repeatable and stateless.

### Recommendation

1. **Add a rate-limiting middleware** to the Node.js REST server (e.g., `express-rate-limit`) applied globally or specifically to endpoints that trigger DB lookups, before the route handlers.
2. **Increase pool size** or use a queue-based connection manager that rejects requests early when the pool is saturated rather than blocking for `connectionTimeout` ms.
3. **Cache negative results**: if a hash lookup returns null, cache that result briefly (e.g., 5 s) so repeated requests for the same non-existent hash do not each hit the DB.
4. **Enforce a minimum hash-prefix length** before issuing the LIKE query, ensuring the index is always used and the query cost is bounded.

### Proof of Concept

```bash
# Send 20 concurrent requests with random non-existent block hashes
for i in $(seq 1 20); do
  HASH=$(openssl rand -hex 32)
  curl -s "http://<mirror-node>/api/v1/contracts/0.0.1/results?block.hash=${HASH}" &
done
wait
# Legitimate request now times out or receives a 500 error
curl -v "http://<mirror-node>/api/v1/contracts/0.0.1/results"
```

Each background request acquires a DB connection and holds it for the duration of the LIKE scan. With the default pool of 10, 10 concurrent requests saturate the pool; the legitimate request at the end will block for up to 20 s and then fail.

### Citations

**File:** rest/controllers/contractController.js (L273-279)
```javascript
const contractResultsFilterValidityChecks = (param, op, val) => {
  const ret = utils.filterValidityChecks(param, op, val);
  if (ret && param === filterKeys.BLOCK_NUMBER) {
    return op === queryParamOperators.eq;
  }
  return ret;
};
```

**File:** rest/controllers/contractController.js (L486-501)
```javascript
    if (blockFilter) {
      let blockData;
      if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
      } else {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
      }

      if (blockData) {
        timestampFilters.push(
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.gte, value: blockData.consensusStart},
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.lte, value: blockData.consensusEnd}
        );
      } else {
        return {skip: true};
      }
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
