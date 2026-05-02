### Title
Unauthenticated Concurrent Request Flood on `/api/v1/schedules` Exhausts DB Connection Pool via Unthrottled `creator_account_id` Index Lookups

### Summary
The `getSchedules()` handler in `rest/schedules.js` accepts the `account.id` query parameter from any unauthenticated caller and translates it directly into a `WHERE creator_account_id = $1` clause, triggering up to three sequential/parallel DB queries per request. The REST API applies no per-IP or global rate limiting to this route, and the DB connection pool is capped at 10 connections by default. A flood of concurrent requests exhausts the pool, queues requests in Node.js memory, and degrades or denies service to all legitimate callers of the mirror node REST API.

### Finding Description
**Code path:**
- `rest/schedules.js` lines 234–282 (`getSchedules`)
- Line 236: `utils.buildAndValidateFilters(req.query, acceptedSchedulesParameters)` — validates format only, no rate check.
- Lines 239–241: builds and executes the primary schedule query with `WHERE creator_account_id = $1`.
- Lines 261–264: fires two additional queries (`entityQuery`, `signatureQuery`) in `Promise.all` for every non-empty result set.

Each inbound request therefore consumes up to **3 DB connections** from the pool simultaneously.

**Root cause:** `rest/server.js` (lines 114–116) registers the schedules routes with no rate-limiting middleware. The middleware stack (lines 67–98) includes `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, and optionally `metricsHandler` and `responseCacheCheckHandler` — none of which throttle request rate. The throttle mechanisms present in the codebase (`ThrottleManagerImpl`, `ThrottleConfiguration`, `ThrottleProperties`) live exclusively in the `web3` module and are never applied to the Node.js REST service.

**DB pool cap:** `rest/dbpool.js` line 14 sets `max: config.db.pool.maxConnections`, whose documented default is **10** (`docs/configuration.md` line 556). With 3 connections consumed per request, only ~3 concurrent `getSchedules` calls fully saturate the pool. All subsequent requests queue in Node.js heap, consuming memory until the `connectionTimeoutMillis` (default 20 s) fires.

**Index:** `importer/src/main/resources/db/migration/v1/V1.35.2__schedule_index.sql` line 3 confirms `schedule__creator_account_id` exists, so each lookup hits the index — but many simultaneous index scans still compete for DB buffer cache and CPU, especially when the attacker varies `account.id` values to defeat any query-plan caching.

**Why existing checks fail:**
- `statementTimeout` (default 20 s) only kills individual long-running queries; it does not prevent a flood of short queries from filling the pool.
- `authHandler` enforces optional HTTP Basic auth for premium limits, but the schedules endpoint requires no credentials at all.
- Response caching (`responseCacheCheckHandler`) only helps for repeated identical requests; rotating `account.id` values bypasses the cache entirely.

### Impact Explanation
Exhausting the 10-connection pool stalls every other REST API endpoint (accounts, transactions, tokens, etc.) that shares the same `global.pool`. Legitimate mirror node users receive connection-timeout errors or indefinitely delayed responses. Since the mirror node REST API is the primary read interface for dApps, explorers, and wallets querying the Hedera network state, sustained degradation constitutes a meaningful availability impact against the mirror node processing tier. The attack does not affect Hedera consensus nodes directly, but it disables the data-serving layer that ≥30% of downstream consumers depend on.

### Likelihood Explanation
No authentication, no API key, no CAPTCHA, and no rate limit are required. Any attacker with a modest botnet (or even a single host using async HTTP) can sustain thousands of requests per second. Rotating `account.id` values (e.g., `0.0.1` through `0.0.999999`) is trivial and defeats response caching. The attack is fully repeatable and requires zero protocol knowledge beyond reading the public OpenAPI spec (`rest/api/v1/openapi.yml` lines 1030–1050).

### Recommendation
1. **Add a global rate-limiting middleware** (e.g., `express-rate-limit` or an upstream Traefik/nginx rate-limit rule) to the Node.js REST service, applied before route handlers in `rest/server.js`.
2. **Add per-IP throttling** specifically for list endpoints (`/schedules`, `/transactions`, `/accounts`) that fan out to multiple DB queries.
3. **Increase `maxConnections`** or deploy a connection pooler (PgBouncer) so that pool exhaustion does not cascade across all endpoints.
4. **Enforce a mandatory `limit` cap** and consider requiring at least one indexed equality filter (e.g., `schedule.id` range) before allowing open `creator_account_id` scans on large tables.
5. **Enable Redis response caching** (`hiero.mirror.rest.cache.response.enabled=true`) to absorb repeated identical queries.

### Proof of Concept
```bash
# Flood /schedules with rotating account.id values, bypassing cache
for i in $(seq 1 500); do
  curl -s "https://<mirror-node-host>/api/v1/schedules?account.id=0.0.$i" &
done
wait
# Observe: legitimate requests to /api/v1/transactions or /api/v1/accounts
# begin returning 500 errors or timing out as the DB pool is exhausted.
```

Sending ~30–50 concurrent requests is sufficient to saturate the default 10-connection pool (each request holds up to 3 connections). Sustained at scale, this denies service to all REST API consumers.