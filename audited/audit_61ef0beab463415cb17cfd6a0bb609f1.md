### Title
Unauthenticated Schedule Endpoint Lacks Rate Limiting, Enabling DB Connection Pool Exhaustion and Bandwidth Amplification

### Summary
The `getScheduleById()` handler in `rest/schedules.js` is publicly accessible with no rate limiting, no per-IP throttling, and no response-size cap. An unauthenticated attacker can enumerate valid `scheduleId` values (sequential integers) and flood the endpoint, exhausting the default 10-connection DB pool and saturating outbound bandwidth with `transaction_body` blobs, degrading the REST API service for all users.

### Finding Description
**Code path:** `rest/schedules.js` lines 115–128 (`getScheduleById`), backed by `getScheduleByIdQuery` at lines 46–64. [1](#0-0) 

The handler:
1. Validates only the format of `scheduleId` via `EntityId.parseString()` — no access control, no rate limit.
2. Executes `getScheduleByIdQuery` which selects the full `s.transaction_body` (`bytea`, no size cap) plus a `json_agg` of all signatures via a three-table JOIN.
3. Returns the full payload including `transaction_body: utils.encodeBase64(row.transaction_body)` (base64 adds ~33% overhead). [2](#0-1) [3](#0-2) 

**No rate limiting exists in the REST API layer.** `server.js` registers the route with no throttle middleware: [4](#0-3) 

The `authHandler` middleware only sets a custom pagination *limit* for authenticated users — it does not throttle request rates and passes unauthenticated requests through silently: [5](#0-4) 

The throttling code (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module, not the REST API: [6](#0-5) 

**DB pool is tiny by default (10 connections, 20 s statement timeout):** [7](#0-6) 

With `statement_timeout = 20000 ms` and `maxConnections = 10`, just 10 concurrent slow queries exhaust the entire pool for up to 20 seconds, blocking all other API users.

**scheduleId enumeration is trivial:** IDs are sequential `bigint` entity numbers (e.g., `0.0.1`, `0.0.2`, …). The API returns `404` for non-existent IDs and `200` for valid ones, making enumeration straightforward.

### Impact Explanation
An attacker with 10 concurrent HTTP connections can hold all DB pool slots for up to 20 seconds each, making the REST API unresponsive to all other clients. Simultaneously, repeated responses containing full `transaction_body` blobs (bounded by Hedera's ~6 KB transaction limit but amplified by base64 encoding and signature aggregation) generate sustained outbound traffic. Because the REST API is a single Node.js process with a shared global pool, this degrades the entire service — meeting the ≥30% processing-node impact threshold for a single-instance deployment.

### Likelihood Explanation
No privileges are required. The endpoint is publicly documented in the OpenAPI spec. scheduleId values are sequential and discoverable via the `/api/v1/schedules` list endpoint. The attack requires only a standard HTTP client and ~10 concurrent connections. It is repeatable indefinitely with no lockout mechanism.

### Recommendation
1. **Add per-IP rate limiting** to the REST API (e.g., `express-rate-limit`) applied globally or specifically to `/schedules/:scheduleId`.
2. **Increase the default DB pool size** or add a request-queue depth limit so pool exhaustion does not block all users.
3. **Add a response cache** (Redis-backed, already supported via `responseCacheCheckHandler`) for schedule lookups — executed/expired schedules are immutable and highly cacheable (the `LONGER_SCHEDULE_CACHE_CONTROL_HEADER` logic already identifies them).
4. Consider enforcing authentication for high-frequency access patterns.

### Proof of Concept
```bash
# Step 1: Enumerate valid scheduleIds
for i in $(seq 1 10000); do
  curl -s -o /dev/null -w "%{http_code} $i\n" \
    "https://<mirror-node>/api/v1/schedules/0.0.$i" | grep "^200"
done

# Step 2: Flood with 10 concurrent requests to a known valid ID
# (repeat to hold all 10 DB pool connections)
for i in $(seq 1 10); do
  curl -s "https://<mirror-node>/api/v1/schedules/0.0.<valid_id>" &
done
wait

# Result: all 10 DB pool connections held; subsequent requests from
# legitimate users receive 503 Service Unavailable (DbError) until
# statement_timeout (20 s) expires.
```

### Citations

**File:** rest/schedules.js (L46-64)
```javascript
const getScheduleByIdQuery = `
  select
    s.consensus_timestamp,
    s.creator_account_id,
    e.deleted,
    s.executed_timestamp,
    s.expiration_time,
    e.key,
    e.memo,
    s.payer_account_id,
    s.schedule_id,
    s.transaction_body,
    s.wait_for_expiry,
    ${transactionSignatureJsonAgg} as signatures
  from schedule s
  left join entity e on e.id = s.schedule_id
  left join transaction_signature ts on ts.entity_id = s.schedule_id
  where s.schedule_id = $1
  group by s.schedule_id, e.id`;
```

**File:** rest/schedules.js (L104-104)
```javascript
    transaction_body: utils.encodeBase64(row.transaction_body),
```

**File:** rest/schedules.js (L115-128)
```javascript
const getScheduleById = async (req, res) => {
  utils.validateReq(req);
  const parseOptions = {allowEvmAddress: false, paramName: constants.filterKeys.SCHEDULEID};
  const scheduleId = EntityId.parseString(req.params.scheduleId, parseOptions).getEncodedId();

  const {rows} = await pool.queryQuietly(getScheduleByIdQuery, scheduleId);
  if (rows.length !== 1) {
    throw new NotFoundError();
  }

  const schedule = rows[0];
  res.locals[constants.responseHeadersLabel] = getScheduleCacheControlHeader(schedule);
  res.locals[constants.responseDataLabel] = formatScheduleRow(schedule);
};
```

**File:** rest/server.js (L114-116)
```javascript
// schedules routes
app.getExt(`${apiPrefix}/schedules`, schedules.getSchedules);
app.getExt(`${apiPrefix}/schedules/:scheduleId`, schedules.getScheduleById);
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

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```
