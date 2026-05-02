### Title
Connection Pool Exhaustion DoS via Unbounded Concurrent Requests in Rosetta API

### Summary
The `ConnectToDb()` function in `rosetta/app/db/db.go` applies `MaxOpenConnections` directly from config with no validation. The `Pool` struct in `rosetta/app/config/types.go` places no lower-bound constraint on this integer field, meaning a value of `0` is silently accepted — and Go's `database/sql` interprets `SetMaxOpenConns(0)` as **unlimited** connections. Combined with the complete absence of application-level rate limiting in the Rosetta API, an unprivileged external attacker can exhaust the DB connection pool (or the DB server itself) with a flood of concurrent requests.

### Finding Description

**Exact code path:**

`rosetta/app/config/types.go`, lines 77–81 — the `Pool` struct carries `MaxOpenConnections int` with no validation tag or minimum-value enforcement: [1](#0-0) 

`rosetta/app/db/db.go`, line 33 — the raw config value is passed directly to `SetMaxOpenConns`: [2](#0-1) 

In Go's `database/sql`, `SetMaxOpenConns(0)` means **no limit** on open connections. If an operator omits the field or explicitly sets it to `0`, the pool becomes unbounded.

**No application-level rate limiting:**

The Rosetta application's middleware stack (`rosetta/main.go` lines 217–219) consists only of `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — none of which throttle requests or limit concurrency: [3](#0-2) 

The `rosetta/app/middleware/` package contains only `metrics.go` and `trace.go`; there is no rate-limiting or in-flight-request-limiting middleware in the application itself.


**Exploit flow:**

1. `MaxOpenConnections` is `0` (or a very large value) — either by operator misconfiguration or by omitting the field (Go zero-value for `int` is `0`).
2. Attacker sends a high volume of concurrent POST requests to any data-fetching Rosetta endpoint (e.g., `/block`, `/account/balance`).
3. Each request causes GORM/`database/sql` to open a new DB connection (pool is unbounded).
4. The PostgreSQL server hits its own `max_connections` limit (default 900 per `charts/hedera-mirror/values.yaml` line 410), begins rejecting connections, and the Rosetta service becomes unavailable. [4](#0-3) 

**Even with the default of 100 connections**, Go's `database/sql` has no built-in wait timeout for acquiring a connection from an exhausted pool. Requests queue indefinitely, causing the service to hang under sustained load from as few as 100 concurrent attackers.

**Why existing checks are insufficient:**

The Traefik middleware (`inFlightReq: amount: 5`, `rateLimit: average: 10`) is gated behind `{{ if and .Values.global.middleware .Values.middleware }}` in the Helm template, making it strictly optional and absent in non-Kubernetes or default deployments: [5](#0-4) 

The `statementTimeout` (default 20 s) limits individual query duration but does not limit how long a goroutine waits to *acquire* a connection from an exhausted pool.

### Impact Explanation
A successful attack renders the Rosetta API completely unresponsive. With `MaxOpenConnections=0`, the PostgreSQL server itself can be crashed or made unavailable, affecting all other mirror-node services sharing the same database. Severity is **High** — full service DoS achievable by any unauthenticated user with the ability to send HTTP requests.

### Likelihood Explanation
The Rosetta API is a public HTTP endpoint. No authentication is required. Sending 100–1000 concurrent HTTP requests is trivially achievable with tools like `wrk`, `hey`, or `ab` from a single machine. The misconfiguration risk (`MaxOpenConnections=0`) is elevated because Go's zero-value for `int` is `0`, meaning any deployment that fails to explicitly set this field in its `application.yml` silently enables an unlimited pool.

### Recommendation

1. **Validate `MaxOpenConnections` at startup** — add a minimum-value check (e.g., `>= 1`) in config loading or in `ConnectToDb()` before calling `SetMaxOpenConns`. Reject or warn loudly on `0`.
2. **Set a DB connection wait timeout** — call `sqlDb.SetConnMaxIdleTime(...)` and use a context with deadline when acquiring connections, so queued requests fail fast rather than hanging.
3. **Add application-level concurrency limiting** — implement an in-flight request limiter (e.g., a semaphore or `golang.org/x/net/netutil.LimitListener`) directly in the Rosetta HTTP server, independent of optional Traefik middleware.
4. **Make Traefik middleware non-optional** — or document clearly that deploying without it exposes the service to DoS.

### Proof of Concept

**Precondition:** Rosetta deployed with `hiero.mirror.rosetta.db.pool.maxOpenConnections: 0` (or field omitted, relying on Go zero-value) and no Traefik middleware active.

```bash
# Install hey (HTTP load generator)
go install github.com/rakyll/hey@latest

# Flood the /network/list endpoint with 500 concurrent workers, 10000 total requests
hey -n 10000 -c 500 -m POST \
  -H "Content-Type: application/json" \
  -d '{"metadata":{}}' \
  http://<rosetta-host>:5700/network/list
```

**Expected result:** PostgreSQL logs show connection count climbing to `max_connections` limit; subsequent requests from legitimate users receive connection errors or hang indefinitely; Rosetta liveness probe at `/health/liveness` begins failing, triggering pod restarts.

### Citations

**File:** rosetta/app/config/types.go (L77-81)
```go
type Pool struct {
	MaxIdleConnections int `yaml:"maxIdleConnections"`
	MaxLifetime        int `yaml:"maxLifetime"`
	MaxOpenConnections int `yaml:"maxOpenConnections"`
}
```

**File:** rosetta/app/db/db.go (L31-33)
```go
	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** charts/hedera-mirror/values.yaml (L410-410)
```yaml
      max_connections: "900"
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```
