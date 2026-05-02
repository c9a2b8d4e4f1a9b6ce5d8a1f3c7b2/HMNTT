### Title
Unauthenticated `/health/readiness` Endpoint Exhausts PostgreSQL Connections via Per-Request `sql.Open`/`db.Close` Cycle

### Summary
The `NewHealthController` function registers a PostgreSQL health check using `postgres.New(postgres.Config{DSN: ...})` from `hellofresh/health-go/v4`. This library's `postgres.New` returns a closure that calls `sql.Open`, `db.PingContext`, and `db.Close` on **every single invocation**. Because the `/health/readiness` endpoint is publicly accessible with no rate limiting, authentication, or result caching, an unprivileged attacker can flood it to open new PostgreSQL connections faster than they are closed, exhausting the server's `max_connections` and denying service to all legitimate application queries.

### Finding Description
**Exact code location:** `rosetta/app/middleware/health.go`, `NewHealthController()`, line 42:
```go
Check: postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),
```

**Root cause:** The `hellofresh/health-go/v4/checks/postgres` package's `New` function returns a closure with this pattern (per the library's published source at v4.7.0):
```go
func New(config Config) func(ctx context.Context) error {
    return func(ctx context.Context) error {
        db, err := sql.Open("postgres", config.DSN)
        if err != nil { return err }
        defer db.Close()
        return db.PingContext(ctx)
    }
}
```
Each call to the returned closure creates a brand-new `*sql.DB` pool, establishes a real TCP connection to PostgreSQL via `PingContext`, and then tears it down via `db.Close()`. There is no shared, persistent connection pool reused across health check invocations.

**No mitigations present:**
- No rate limiting or throttling on the `/health/readiness` route (confirmed: `grep` for `rateLimit`, `throttle`, `limit.*request` in `rosetta/**/*.go` returns zero matches).
- No authentication or IP allowlist on the health endpoint.
- The `health.Config` struct used at lines 37–43 sets no `MaxConcurrent` field and no result-caching TTL, so every HTTP request triggers a fresh check execution.
- The application's own DB pool (`rosetta/app/db/db.go`, lines 31–33) is separate from the health-check connection; the health check bypasses it entirely.

**Exploit flow:**
1. Attacker sends N concurrent `GET /health/readiness` requests.
2. The `hellofresh/health-go` handler runs all registered checks for each request.
3. Each request's postgresql check calls `sql.Open` → `PingContext` (opens a real PG connection) → `db.Close`.
4. Under high concurrency, many connections are simultaneously in the `PingContext` phase before `db.Close` is reached.
5. PostgreSQL's `max_connections` (default: 100) is exhausted.
6. All subsequent connection attempts—including those from the application's own GORM pool—receive `FATAL: sorry, too many clients already`.

### Impact Explanation
When `max_connections` is exhausted on the PostgreSQL server, every component sharing that server (the Rosetta API's GORM pool, the importer, REST API, etc.) fails to acquire connections. All database-backed API calls return errors. This is a full application-layer denial of service achievable without any credentials or prior access. The health endpoint is typically exposed on the same port as the API (configured via `rosettaConfig.Port`), making it reachable by any network-adjacent or internet-facing attacker.

### Likelihood Explanation
The attack requires only the ability to send HTTP GET requests—no authentication, no special headers, no knowledge of internal state. A single attacker with a modest HTTP flood tool (e.g., `wrk`, `ab`, `hey`) can sustain hundreds of concurrent requests. The 10-second `Timeout` per check means connections can be held open for up to 10 seconds each, amplifying the connection-exhaustion window. This is repeatable and automatable with zero skill barrier.

### Recommendation
1. **Replace the per-invocation `sql.Open` pattern** by constructing a persistent `*sql.DB` once (outside the closure) and passing it to the health check, or use a custom check that reuses the application's existing GORM/`sql.DB` pool to run a `SELECT 1` ping.
2. **Add rate limiting** to the `/health/readiness` route (e.g., via a token-bucket middleware) to cap the number of check executions per second.
3. **Cache health check results** using `hellofresh/health-go`'s built-in `WithTimeout` or a result-cache TTL so that concurrent requests within a short window reuse the last result rather than each triggering a new DB connection.
4. **Restrict network access** to the health endpoints to known orchestration sources (Kubernetes probes, load balancer IPs) via network policy or a middleware IP allowlist.

### Proof of Concept
```bash
# Prerequisites: rosetta service running, /health/readiness reachable at $HOST:$PORT
# Tool: wrk (or hey, ab)

# Send 200 concurrent connections for 30 seconds
wrk -t 20 -c 200 -d 30s http://$HOST:$PORT/health/readiness

# On the PostgreSQL server, observe connection count:
psql -c "SELECT count(*) FROM pg_stat_activity;"
# Count will spike toward max_connections (default 100)

# Simultaneously, attempt a legitimate API call:
curl http://$HOST:$PORT/network/list
# Returns 500 / connection error once max_connections is exhausted

# On PostgreSQL logs:
# FATAL:  sorry, too many clients already
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/health.go (L37-43)
```go
	readinessChecks := []health.Config{
		{
			Name:      "postgresql",
			Timeout:   time.Second * 10,
			SkipOnErr: false,
			Check:     postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),
		},
```

**File:** rosetta/app/middleware/health.go (L63-78)
```go
func (c *healthController) Routes() server.Routes {
	return server.Routes{
		{
			"liveness",
			"GET",
			livenessPath,
			c.livenessHealth.HandlerFunc,
		},
		{
			"readiness",
			"GET",
			readinessPath,
			c.readinessHealth.HandlerFunc,
		},
	}
}
```

**File:** rosetta/app/db/db.go (L31-33)
```go
	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```
