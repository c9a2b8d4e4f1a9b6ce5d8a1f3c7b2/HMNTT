### Title
Unauthenticated DB Connection Pool Exhaustion via Unbounded Concurrent Requests in Rosetta API

### Summary
`GetDbWithContext()` in `rosetta/app/db/client.go` creates a `context.WithTimeout()` for every call, bounding each DB connection acquisition to `statementTimeout` seconds (default: 20s). Because the Rosetta HTTP server applies no application-level concurrency or rate-limiting middleware, any unprivileged external attacker can flood the server with concurrent requests, saturating the fixed-size connection pool (`MaxOpenConnections=100` by default) and causing all legitimate queries to block or fail for the duration of the attack.

### Finding Description
**Exact code path:**

- `rosetta/app/db/client.go`, `GetDbWithContext()`, lines 22–38: every call with `statementTimeout > 0` creates a child context via `context.WithTimeout(ctx, time.Duration(d.statementTimeout)*time.Second)` and returns a `*gorm.DB` bound to that context. The connection is held for the entire query execution, up to `statementTimeout` seconds.
- `rosetta/app/db/db.go`, `ConnectToDb()`, lines 31–33: the pool is configured with `SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)`. Default per documentation: `maxOpenConnections=100`, `statementTimeout=20` (seconds).
- `rosetta/main.go`, lines 217–227: the HTTP server chain is `MetricsMiddleware → TracingMiddleware → CorsMiddleware`. There is no concurrency-limiting or rate-limiting middleware at the application layer.
- `charts/hedera-mirror-rosetta/values.yaml`, line 95: `global.middleware: false` — the Traefik `inFlightReq` (amount: 5 per IP) and `rateLimit` (average: 10/host) middlewares defined at lines 152–160 are **not applied** in a default deployment because the guard condition `{{ if and .Values.global.middleware .Values.middleware }}` evaluates to false.

**Root cause:** The application assumes an external proxy enforces concurrency limits, but that proxy-level protection is disabled by default. There is no fallback in-process guard.

**Failed assumption:** The design assumes Traefik middleware will always be active in front of the Rosetta service. In practice, `global.middleware` defaults to `false`, leaving the application directly exposed with no concurrency control.

**Exploit flow:**
1. Attacker opens 100+ concurrent HTTP connections to the Rosetta API (no authentication required).
2. Each request reaches a repository method (e.g., `RetrieveBalanceAtBlock`, `findBlockByHash`) that calls `GetDbWithContext()`, acquires a DB connection, and holds it while the query runs (up to 20 seconds).
3. Once all 100 pool slots are occupied, `database/sql` blocks new callers waiting for a free connection.
4. Legitimate user requests queue indefinitely or time out at the HTTP layer (`writeTimeout=10s` default), returning errors.

### Impact Explanation
Availability of the entire Rosetta API is lost for the duration of the attack. All endpoints that call `GetDbWithContext()` — account balance, block lookup, transaction queries — are affected simultaneously. No funds are directly at risk (read-only mirror API), consistent with the Medium severity classification. Recovery requires the attacker to stop sending requests and the 20-second statement timeouts to expire, releasing connections back to the pool.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only a standard HTTP client capable of maintaining ~100 concurrent connections — trivially achievable with tools like `wrk`, `hey`, or a simple script. The default deployment configuration (Traefik middleware disabled) means the vast majority of deployments are exposed out of the box. The attack is repeatable and cheap to sustain.

### Recommendation
1. **Application-level semaphore:** Add an in-process `http.Handler` middleware that enforces a maximum number of concurrent in-flight requests (e.g., using a buffered channel or `golang.org/x/sync/semaphore`) before any DB work begins. Reject excess requests with HTTP 429.
2. **Enable Traefik middleware by default:** Change `global.middleware` default to `true` in `charts/hedera-mirror-rosetta/values.yaml` so the `inFlightReq` and `rateLimit` guards are active in all standard deployments.
3. **Reduce default pool/timeout exposure:** Consider lowering `statementTimeout` and `maxOpenConnections` to values that limit the blast radius, or add a `connectionTimeout` so pool-wait failures are fast rather than blocking.

### Proof of Concept
```bash
# Requires: wrk or hey; Rosetta running at localhost:5700 with default config
# (global.middleware=false, maxOpenConnections=100, statementTimeout=20s)

# Step 1: Flood with 150 concurrent connections, each triggering a DB query
hey -n 100000 -c 150 -m POST \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"block_identifier":{"index":1}}' \
  http://localhost:5700/block

# Step 2: In a separate terminal, send a legitimate request and observe timeout/error
curl -s -X POST http://localhost:5700/block \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"block_identifier":{"index":1}}'
# Expected: connection wait timeout or HTTP 500 (ErrDatabaseError) while pool is exhausted
```