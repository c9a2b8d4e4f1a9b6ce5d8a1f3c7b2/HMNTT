### Title
Unbounded `maxConnections` Pool Configuration Enables PostgreSQL Connection Exhaustion via Unauthenticated Request Flood

### Summary
`initializePool()` in `rest/dbpool.js` creates a `pg` Pool with `max` set directly from `config.db.pool.maxConnections`, which `parseDbPoolConfig()` in `rest/config.js` validates only as a positive integer — no upper bound is enforced. With no rate-limiting middleware in `server.js`, an unauthenticated attacker flooding the public REST API with concurrent requests can drive the pool to open up to the misconfigured `maxConnections` value, exhausting PostgreSQL's `max_connections` and denying all other services (importer, monitor, etc.) any new database connections.

### Finding Description
**Code path:**

- `rest/config.js` lines 137–148 (`parseDbPoolConfig`): validates only `parsed <= 0`, no ceiling check on `maxConnections`.
- `rest/dbpool.js` lines 7–16: `poolConfig.max` is set directly to `config.db.pool.maxConnections`.
- `rest/dbpool.js` lines 35–47 (`initializePool`): creates `global.pool` (and optionally `global.primaryPool` when `config.db.primaryHost` is set — two pools, doubling the cap) with no additional guard.
- `rest/server.js` lines 67–98: middleware stack contains `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler` — **no rate-limiting or concurrency-limiting middleware**.

**Root cause:** `parseDbPoolConfig` enforces `> 0` but not `<= some_safe_ceiling`. An operator can set `maxConnections: 10000` (or any large value) and the code accepts it silently. The `pg` Pool opens connections lazily up to `max`; once all `max` slots are in use, new requests queue — but if `max` exceeds PostgreSQL's `max_connections`, the pool will have already opened more connections than PostgreSQL can serve.

**Why existing checks fail:** The only guard is `parsed <= 0` at config load time. There is no runtime check, no HTTP-layer concurrency cap, and no enforcement that `maxConnections` stays below PostgreSQL's `max_connections`.

### Impact Explanation
If `maxConnections` is misconfigured to a value exceeding PostgreSQL's `max_connections` (default: 100), an attacker driving enough concurrent unauthenticated requests causes the pool to hold all available PostgreSQL connections. Every other service — the importer writing new consensus data, the monitor, any other REST instance — is refused new connections. No new transaction queries can be executed, effectively halting the mirror node's ability to confirm or serve new transactions. Severity: **Critical** (total read/write denial of service against the shared database).

### Likelihood Explanation
The REST API is public and unauthenticated by default (the `authHandler` only optionally enforces response-size limits, not access control). Any external actor can issue concurrent HTTP GET requests to any endpoint (e.g., `/api/v1/transactions`) with no credential requirement. Flooding with concurrent requests is trivially scriptable (`ab`, `wrk`, `hey`, etc.). The precondition — a misconfigured large `maxConnections` — is realistic in environments where operators raise the pool size to improve throughput without coordinating with the PostgreSQL `max_connections` setting. When `primaryHost` is also configured, two pools are created, halving the threshold needed to exhaust PostgreSQL.

### Recommendation
1. **Enforce an upper bound in `parseDbPoolConfig`**: add a check such as `parsed > SAFE_MAX_CONNECTIONS_CEILING` (e.g., 100 or a configurable PostgreSQL-aware limit) and throw `InvalidConfigError`.
2. **Add HTTP concurrency / rate-limiting middleware** (e.g., `express-rate-limit`) in `server.js` before route handlers to cap requests per IP.
3. **Reserve PostgreSQL connections** for non-REST services using PostgreSQL's `pg_hba.conf` `connection_limit` per role, so the REST API's pool can never consume all available slots.
4. **When `primaryHost` is set**, account for both pools' combined `maxConnections` against the PostgreSQL ceiling.

### Proof of Concept
**Preconditions:**
- `hiero.mirror.rest.db.pool.maxConnections` set to a value ≥ PostgreSQL's `max_connections` (e.g., 200 when PostgreSQL has `max_connections=100`).
- REST API running and publicly accessible on port 5551.

**Steps:**
```bash
# 1. Confirm no rate limiting — send 200 concurrent unauthenticated requests
wrk -t 20 -c 200 -d 30s http://<mirror-node-host>:5551/api/v1/transactions

# 2. While the flood is running, observe PostgreSQL connection count:
psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;"
# → count approaches max_connections (e.g., 100)

# 3. Attempt a new connection from the importer or another service:
psql -U mirror_node mirror_node -c "SELECT 1;"
# → ERROR: remaining connection slots are reserved for non-replication superuser connections
#   (or: FATAL: sorry, too many clients already)

# 4. Result: no new transaction queries can be executed; mirror node halts ingestion.
```