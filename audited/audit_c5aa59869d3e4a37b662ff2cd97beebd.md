### Title
Unauthenticated Pagination Flood via `limit=1` Exhausts DB Connection Pool in Block API

### Summary
The `generateNextLink()` function in `rest/controllers/blockController.js` unconditionally returns a next-page link whenever `blocks.length === filters.limit`. With `limit=1` (a valid, accepted value), every response for a non-empty block range includes a next link. Because the REST API has no per-IP rate limiting middleware and the default DB connection pool is only 10 connections, an unauthenticated attacker can flood the server with concurrent paginated requests, each consuming a pool connection for up to 20 seconds, starving legitimate traffic of DB access.

### Finding Description

**Exact code path:**

`generateNextLink()` at `rest/controllers/blockController.js` lines 90–99:
```js
generateNextLink = (req, blocks, filters) => {
  return blocks.length
    ? utils.getPaginationLink(
        req,
        blocks.length !== filters.limit,   // isEnd = false when blocks.length == limit
        {[filterKeys.BLOCK_NUMBER]: last(blocks).index},
        filters.order
      )
    : null;
};
``` [1](#0-0) 

When `limit=1`, `blocks.length` is always `1` and `filters.limit` is always `1`, so `isEnd` is always `false` and a next link is always emitted — for every block in the chain.

**`limit=1` is accepted without restriction:**

`extractLimitFromFilters` only rejects values strictly greater than `maxLimit` (default 100); `limit=1` passes through unchanged. [2](#0-1) 

**No rate limiting on the REST API:**

`server.js` registers `authHandler`, `requestLogger`, `metricsHandler`, and `responseCacheCheckHandler` — no per-IP or global request-rate limiter exists for the Node.js REST service. [3](#0-2) 

The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) is scoped exclusively to the `web3` Spring Boot module and does not protect the Node.js REST API. [4](#0-3) 

**DB pool is tiny:**

The default pool is 10 connections with a 20-second statement timeout. [5](#0-4) [6](#0-5) 

Each `getBlocks` call acquires one pool connection for the duration of the query. [7](#0-6) 

### Impact Explanation

With 10 pool connections and a 20-second statement timeout, an attacker needs only 10 concurrent in-flight requests to hold every connection. All legitimate requests then queue or time out (`connectionTimeoutMillis = 20000 ms`). Block data becomes unavailable to all other clients for the duration of the attack. Because blocks are append-only and the chain grows continuously, the attacker's cursor advances indefinitely — the attack never self-terminates.

### Likelihood Explanation

No authentication, no CAPTCHA, no rate limit, and no minimum-limit enforcement are required. Any HTTP client capable of sending 10 concurrent requests (e.g., `curl`, `ab`, `wrk`) can trigger this from a single IP. The attack is trivially scriptable, repeatable, and requires zero knowledge of the system beyond the public API spec.

### Recommendation

1. **Add a rate-limiting middleware** (e.g., `express-rate-limit`) to the Node.js REST API, applied globally before route handlers, with per-IP limits.
2. **Enforce a minimum effective limit** (e.g., `limit >= 5`) or increase the default pool size significantly.
3. **Add a concurrency cap** per IP at the reverse-proxy/ingress layer (e.g., Nginx `limit_conn`).
4. Optionally, enforce a minimum `limit` value in `extractLimitFromFilters` to reduce query amplification.

### Proof of Concept

```bash
# Assuming blocks 1..10000 exist on the node
# Send 20 concurrent requests, each holding a DB connection for ~20s
for i in $(seq 1 20); do
  curl -s "http://<host>/api/v1/blocks?limit=1&block.number=gt:$((i*1000))" &
done
wait

# Legitimate request now times out or receives a connection-pool error:
curl -v "http://<host>/api/v1/blocks?limit=25"
# Expected: 503 / connection timeout after 20s
```

Each background request causes `getBlocks` to acquire a pool connection. With 20 concurrent requests and only 10 pool slots, the pool is exhausted and the final legitimate request cannot obtain a connection within `connectionTimeoutMillis`.

### Citations

**File:** rest/controllers/blockController.js (L57-61)
```javascript
  extractLimitFromFilters = (filters) => {
    const limit = findLast(filters, {key: filterKeys.LIMIT});
    const maxLimit = getEffectiveMaxLimit();
    return limit ? (limit.value > maxLimit ? defaultLimit : limit.value) : defaultLimit;
  };
```

**File:** rest/controllers/blockController.js (L90-99)
```javascript
  generateNextLink = (req, blocks, filters) => {
    return blocks.length
      ? utils.getPaginationLink(
          req,
          blocks.length !== filters.limit,
          {[filterKeys.BLOCK_NUMBER]: last(blocks).index},
          filters.order
        )
      : null;
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

**File:** rest/server.js (L82-98)
```javascript
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
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
