### Title
Unauthenticated DoS via Unbounded Concurrent `ILIKE '%X%'` Queries Exhausting the REST DB Connection Pool

### Summary
The `extractSqlFromTokenRequest()` function in `rest/tokens.js` constructs an `ILIKE '%X%'` query for the `name` filter with no per-IP or per-endpoint rate limiting on the REST API. Although a GIN trigram index exists on `token.name`, common 3-byte patterns (e.g., `tok`, `USD`) can still match a large fraction of the token table, producing expensive index-scan + join operations. With the default connection pool capped at 10 connections and a 20-second statement timeout, an attacker flooding concurrent requests can exhaust all DB connections and deny service to legitimate users.

### Finding Description

**Exact code path:**

`rest/tokens.js`, `extractSqlFromTokenRequest()`, lines 176–178: [1](#0-0) 

```js
if (filter.key === filterKeys.NAME) {
  conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
}
```

The validation gate in `validateTokenQueryFilter()` (line 333–335): [2](#0-1) 

```js
case filterKeys.NAME:
  ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
  break;
```

`isByteRange` (line 131–133 in `rest/utils.js`) only checks byte length: [3](#0-2) 

**Root cause:** The minimum 3-byte constraint is the only content restriction on the `name` parameter. A GIN trigram index does exist: [4](#0-3) 

This prevents pure sequential scans for patterns ≥ 3 characters. However, for high-frequency trigrams (e.g., `tok`, `USD`, `BTC`, `the`) that appear in a large fraction of token names, PostgreSQL may fall back to a sequential scan (planner cost threshold) or the GIN index scan itself returns a massive posting list, requiring a full join against `entity e`. Either path is expensive.

**No rate limiting exists on the REST API.** The throttle infrastructure found in the codebase is exclusively for the `web3` Java service: [5](#0-4) 

The grep for `rateLimit|throttle` in `rest/**/*.js` returns zero matches.

**Connection pool is small by default:** [6](#0-5) 

Default `maxConnections = 10` (documented in `docs/configuration.md` line 556). Statement timeout is 20 seconds: [7](#0-6) 

**Exploit flow:**
1. Attacker identifies a common 3-byte substring present in many token names (e.g., `tok`).
2. Attacker sends ≥10 concurrent `GET /api/v1/tokens?name=tok` requests.
3. Each request acquires a DB connection and executes: `SELECT … FROM token t JOIN entity e … WHERE t.name ILIKE $1` with `$1 = '%tok%'`.
4. Each query holds its connection for up to 20 seconds (statement timeout).
5. The pool of 10 connections is exhausted; all subsequent legitimate requests queue or fail with a connection timeout error.
6. Attacker repeats continuously to maintain the denial of service.

### Impact Explanation
The REST API's DB connection pool (default 10, max 250 per Helm config) is a finite shared resource. Exhausting it prevents all other REST API endpoints from executing queries, degrading or completely blocking mirror node availability. This maps directly to the stated severity: sustained degradation of mirror node processing without brute-force actions, achievable by a single attacker with no credentials.

### Likelihood Explanation
No authentication, API key, or rate limiting is required. Any internet-accessible mirror node deployment is vulnerable. The attack requires only a standard HTTP client and knowledge of a common token name substring. It is trivially repeatable and automatable. The 20-second statement timeout means only ~0.5 requests/second per connection slot is needed to maintain saturation.

### Recommendation
1. **Add rate limiting to the REST API** (e.g., `express-rate-limit` middleware) scoped to the `/api/v1/tokens` endpoint, limiting requests per IP per second.
2. **Increase the minimum `name` length** from 3 bytes to a value that ensures high trigram selectivity (e.g., 6–8 bytes), reducing the fraction of the table matched.
3. **Add a query result-count guard**: use `LIMIT` at the DB level before the join, or add a `statement_timeout` override specifically for name-search queries that is shorter than the global 20-second timeout.
4. **Consider caching** name-search results in Redis (the infrastructure already exists per `docs/configuration.md` line 549) with a short TTL to absorb repeated identical queries.

### Proof of Concept
```bash
# Identify a common 3-byte substring (e.g., "tok" appears in many Hedera token names)
# Send 15 concurrent requests to exhaust the default pool of 10 connections
for i in $(seq 1 15); do
  curl -s "https://<mirror-node>/api/v1/tokens?name=tok" &
done
wait

# Verify: subsequent legitimate requests time out or return 503
curl -v "https://<mirror-node>/api/v1/transactions?limit=1"
# Expected: connection timeout or HTTP 503 Service Unavailable
```

### Citations

**File:** rest/tokens.js (L176-178)
```javascript
    if (filter.key === filterKeys.NAME) {
      conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
    }
```

**File:** rest/tokens.js (L333-335)
```javascript
    case filterKeys.NAME:
      ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
      break;
```

**File:** rest/utils.js (L131-133)
```javascript
const isByteRange = (str, minSize, maxSize) => {
  const length = Buffer.from(str).length;
  return length >= minSize && length <= maxSize;
```

**File:** importer/src/main/resources/db/migration/v2/V2.3.2__token_name_index.sql (L1-1)
```sql
create index if not exists token__name on token using gin (name gin_trgm_ops);
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

**File:** charts/hedera-mirror/templates/secret-passwords.yaml (L124-124)
```yaml
    alter user {{ $restUsername }} set statement_timeout to '20000';
```
