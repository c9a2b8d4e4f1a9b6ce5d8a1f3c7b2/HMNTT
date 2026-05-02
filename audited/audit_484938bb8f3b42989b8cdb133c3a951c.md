### Title
Unauthenticated Connection Pool Exhaustion via Concurrent Request Flood in REST API

### Summary
The `initializePool()` function in `rest/dbpool.js` creates `global.pool` with a default maximum of 10 connections and no per-client concurrency or rate limiting in the REST API middleware stack. An unauthenticated attacker can flood the server with concurrent requests, each holding a DB connection for up to the `statement_timeout` window (20 seconds by default), continuously replacing timed-out connections to sustain pool exhaustion and cause `connectionTimeoutMillis` errors for all legitimate requests.

### Finding Description

**Exact code location:**

`rest/dbpool.js`, `initializePool()`, lines 35–46: [1](#0-0) 

The pool is configured with:
- `max: config.db.pool.maxConnections` → default **10**
- `connectionTimeoutMillis: config.db.pool.connectionTimeout` → default **20,000 ms**
- `statement_timeout: config.db.pool.statementTimeout` → default **20,000 ms** [2](#0-1) 

Documented defaults confirm these values: [3](#0-2) 

**No rate limiting in the REST API middleware stack.** `server.js` registers: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — none of which limit concurrent connections or request rate per IP: [4](#0-3) 

`authHandler` only sets a custom response-row limit for authenticated users; it performs no rate limiting and unauthenticated requests pass through freely: [5](#0-4) 

The throttle/rate-limit infrastructure (bucket4j) exists only in the `web3` Java service, not in the Node.js REST API: [6](#0-5) 

**Root cause:** The pool's `max` of 10 is a hard ceiling on concurrent DB clients. `statement_timeout` bounds each individual query to 20 seconds but does not prevent an attacker from continuously issuing new requests to replace connections as they are released. With no concurrency or rate guard at the HTTP layer, the attacker needs only to sustain ≥10 in-flight DB-hitting requests at any moment — trivially achievable with a simple HTTP flood tool.

**Exploit flow:**
1. Attacker opens 10+ concurrent HTTP connections to any DB-backed endpoint (e.g., `GET /api/v1/transactions`).
2. Each request acquires one pool connection and holds it while the query executes (up to 20 s).
3. All 10 pool slots are occupied; `global.pool` is saturated.
4. Legitimate requests queue for a connection; after `connectionTimeoutMillis` (20 s) they receive an error.
5. Attacker sends replacement requests every few seconds (≥1 request per 2 s sustains exhaustion with 10 connections × 20 s timeout), maintaining continuous saturation.

**Why `statement_timeout` is insufficient:** It caps the duration a single connection is held, but does not cap the rate at which new connections are acquired. The attacker's throughput requirement to sustain exhaustion is `maxConnections / statementTimeout` = 10/20 = 0.5 requests/second — well within reach of any HTTP client.

### Impact Explanation

All legitimate API consumers receive connection timeout errors (`Error: timeout exceeded when trying to connect`) for the duration of the attack. The REST API is effectively partitioned from its database. Since `global.pool` is a process-global singleton initialized once at startup, there is no per-request fallback. Severity: **High** — complete denial of service of the REST API's database layer, requiring no credentials.

### Likelihood Explanation

Preconditions: none. The attacker needs only network access to the REST API port (5551 by default). The attack is reproducible with any HTTP load tool (`ab`, `wrk`, `curl` in a loop). The required sustained rate (0.5 req/s) is negligible. The attack is repeatable indefinitely and leaves no persistent state to clean up.

### Recommendation

1. **Add a concurrency/rate-limit middleware** to the Express stack (e.g., `express-rate-limit` or `bottleneck`) before route handlers, limiting concurrent in-flight requests per IP and/or globally.
2. **Increase `maxConnections`** to match realistic concurrency, or deploy a connection pooler (PgBouncer in transaction mode) in front of PostgreSQL to absorb bursts — the Helm chart already configures PgBouncer with `max_user_client_connections: 1000` and `max_user_connections: 250` for `mirror_rest`, but this only helps if the REST API itself is also protected upstream.
3. **Add an ingress-level `inFlightReq` limit** (as already done for the Rosetta service in `charts/hedera-mirror-rosetta/values.yaml` lines 152–156) to the REST API ingress.
4. Consider reducing `statement_timeout` to a lower value (e.g., 5 s) to shrink the exhaustion window per connection.

### Proof of Concept

```bash
# Exhaust all 10 pool connections with concurrent slow requests
# (any endpoint that hits the DB; timestamp range queries tend to be heavier)
for i in $(seq 1 15); do
  curl -s "http://<REST_API_HOST>:5551/api/v1/transactions?timestamp=gte:0000000001&timestamp=lte:9999999999&limit=100" &
done
wait

# Now send a legitimate request — it will time out after connectionTimeoutMillis (20 s)
time curl -v "http://<REST_API_HOST>:5551/api/v1/transactions"
# Expected: connection timeout error after ~20 seconds
```

Repeat the flood loop every 15 seconds to maintain continuous exhaustion.

### Citations

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

**File:** rest/dbpool.js (L35-47)
```javascript
const initializePool = () => {
  global.pool = new Pool(poolConfig);
  handlePoolError(global.pool);

  if (config.db.primaryHost) {
    const primaryPoolConfig = {...poolConfig};
    primaryPoolConfig.host = config.db.primaryHost;
    global.primaryPool = new Pool(primaryPoolConfig);
    handlePoolError(global.primaryPool);
  } else {
    global.primaryPool = pool;
  }
};
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
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
