### Title
Missing Timestamp Range Validation on `/blocks` Endpoint Enables Connection Pool Exhaustion via Flooding

### Summary
The `GET /blocks` endpoint in the REST API does not apply the configured `maxTimestampRange` validation that is enforced on other endpoints. An unprivileged attacker can supply an arbitrarily wide timestamp range with maximum `limit`, and by flooding the service with concurrent such requests, exhaust the database connection pool and cause denial of service.

### Finding Description

**Code path:**

`blockRoute.js` routes `GET /` to `BlockController.getBlocks`. [1](#0-0) 

`BlockController.getBlocks` calls `buildAndValidateFilters`, then `extractSqlFromBlockFilters`, then `RecordFileService.getBlocks`. [2](#0-1) 

`extractSqlFromBlockFilters` maps timestamp filters directly to SQL WHERE conditions via `getFilterWhereCondition` — it never calls `parseTimestampFilters` (the function that enforces `maxTimestampRangeNs`). [3](#0-2) 

`RecordFileService.getBlocks` executes the query with the unchecked timestamp range and a `LIMIT` clause. The `blocksQuery` also selects `coalesce(size, length(bytes)) as size`, which forces reading the potentially large `bytes` column for each returned row. [4](#0-3) [5](#0-4) 

**Root cause — failed assumption:**

The system has a `maxTimestampRange` config (default 7 days) and a `parseTimestampFilters` utility that enforces it: [6](#0-5) 

This guard is applied to other endpoints (e.g., contract results, transactions) but is **entirely absent** from the blocks controller. The `extractLimitFromFilters` caps rows at `maxLimit` (default 100), but this only bounds result size, not query scan cost or connection hold time. [7](#0-6) 

There is no rate-limiting middleware on the Node.js REST API blocks endpoint. The throttle/rate-limit infrastructure found in the codebase applies only to the separate `web3` Java service. [8](#0-7) 

The DB pool has a `statementTimeout` and `maxConnections`, but these only bound individual query duration and total connections — they do not prevent pool exhaustion when many concurrent requests each hold a connection for the full `statementTimeout` duration. [9](#0-8) 

### Impact Explanation
Each concurrent request to `GET /blocks?timestamp=gte:1000000000&timestamp=lte:9999999999&limit=100` acquires a database connection and holds it for the duration of the query (up to `statementTimeout`). With no rate limiting and no timestamp range guard, an attacker can open enough concurrent connections to exhaust the pool (`maxConnections`, default small). Once the pool is exhausted, all subsequent requests — including legitimate ones — receive connection timeout errors, resulting in full API denial of service. The `coalesce(size, length(bytes))` in the SELECT amplifies per-query cost by forcing reads of a binary column.

### Likelihood Explanation
No authentication or privilege is required. The attack requires only the ability to send HTTP GET requests. It is trivially scriptable (e.g., `ab`, `wrk`, or a simple loop). The absence of any per-IP or per-endpoint rate limiting on the REST API makes it repeatable and sustainable. Any public-facing deployment is exposed.

### Recommendation
1. Apply `parseTimestampFilters` with `validateRange: true` inside `extractSqlFromBlockFilters` for timestamp filters, consistent with other endpoints, to reject ranges exceeding `maxTimestampRange` (7 days by default).
2. Add per-IP or global rate limiting middleware to the REST API (e.g., `express-rate-limit`) covering the `/blocks` route.
3. Consider excluding the `bytes` column from `blocksQuery` or computing `length(bytes)` only when `size` is null and the column is needed, to reduce per-query I/O.

### Proof of Concept
```bash
# Flood with 200 concurrent wide-range block queries
for i in $(seq 1 200); do
  curl -s "http://<mirror-node-rest>:5551/api/v1/blocks?timestamp=gte:1000000000&timestamp=lte:9999999999&limit=100" &
done
wait
# Subsequent legitimate requests will receive 503 / connection pool exhausted errors
curl "http://<mirror-node-rest>:5551/api/v1/blocks"
```

### Citations

**File:** rest/routes/blockRoute.js (L12-12)
```javascript
router.getExt('/', BlockController.getBlocks);
```

**File:** rest/controllers/blockController.js (L57-61)
```javascript
  extractLimitFromFilters = (filters) => {
    const limit = findLast(filters, {key: filterKeys.LIMIT});
    const maxLimit = getEffectiveMaxLimit();
    return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
  };
```

**File:** rest/controllers/blockController.js (L63-88)
```javascript
  extractSqlFromBlockFilters = (filters) => {
    const filterQuery = {
      order: this.extractOrderFromFilters(filters),
      orderBy: this.extractOrderByFromFilters(filters),
      limit: this.extractLimitFromFilters(filters),
      whereQuery: [],
    };

    if (filters && filters.length === 0) {
      return filterQuery;
    }

    filterQuery.whereQuery = filters
      .filter((f) => blockWhereFilters.includes(f.key))
      .map((f) => {
        switch (f.key) {
          case filterKeys.BLOCK_NUMBER:
            return this.getFilterWhereCondition(RecordFile.INDEX, f);

          case filterKeys.TIMESTAMP:
            return this.getFilterWhereCondition(RecordFile.CONSENSUS_END, f);
        }
      });

    return filterQuery;
  };
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

**File:** rest/service/recordFileService.js (L64-70)
```javascript
  static blocksQuery = `select
    ${RecordFile.COUNT}, ${RecordFile.HASH}, ${RecordFile.NAME}, ${RecordFile.PREV_HASH},
    ${RecordFile.HAPI_VERSION_MAJOR}, ${RecordFile.HAPI_VERSION_MINOR}, ${RecordFile.HAPI_VERSION_PATCH},
    ${RecordFile.INDEX}, ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.GAS_USED},
    ${RecordFile.LOGS_BLOOM}, coalesce(${RecordFile.SIZE}, length(${RecordFile.BYTES})) as size
    from ${RecordFile.tableName}
  `;
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

**File:** rest/utils.js (L1657-1665)
```javascript
  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
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
