### Title
Unauthenticated `/health/readiness` Endpoint Causes Per-Request PostgreSQL Connection Churn via `hellofresh/health-go` Postgres Check

### Summary
The `/health/readiness` endpoint in `rosetta/app/middleware/health.go` is publicly accessible with no authentication or rate limiting at the application layer. It uses `github.com/hellofresh/health-go/v4/checks/postgres`, which calls `sql.Open()` + `db.PingContext()` + `db.Close()` on **every single invocation**, creating and destroying a fresh PostgreSQL connection per request. An unprivileged external attacker can flood this endpoint to cause sustained connection churn, exhausting PostgreSQL's `max_connections` budget and degrading query performance for legitimate users.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/health.go`, `NewHealthController()`, line 42:
```go
Check: postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),
``` [1](#0-0) 

`Routes()` at line 63 registers this handler at `GET /health/readiness` with no authentication wrapper, no rate-limit middleware, and no concurrency guard: [2](#0-1) 

**Root cause — `hellofresh/health-go/v4/checks/postgres` behavior:**
The `postgres.New()` check function, per the library's public source, executes on every HTTP request:
1. `sql.Open("postgres", dsn)` — allocates a new driver-level connection pool
2. `db.PingContext(ctx)` — establishes a real TCP connection to PostgreSQL and authenticates
3. `db.Close()` — tears down the pool and closes the connection

There is no persistent connection or pool reuse between health check invocations. Each HTTP request to `/health/readiness` maps 1:1 to a full PostgreSQL connect/authenticate/disconnect cycle.

**No rate limiting applies to this path:**
The Traefik middleware chain (rate limit, circuit breaker, inFlightReq) is configured only for the `/rosetta/*` ingress paths: [3](#0-2) [4](#0-3) 

`/health/readiness` is absent from the ingress path list, so the Traefik middleware is never applied to it. The Go HTTP server itself (`main.go` line 220–227) applies no per-route rate limiting: [5](#0-4) 

The application-level middleware stack (`MetricsMiddleware`, `TracingMiddleware`, `CorsMiddleware`) contains no throttling: [6](#0-5) 

### Impact Explanation
Each flood request consumes one PostgreSQL connection slot for the duration of the TCP handshake + auth + ping + teardown (~5–50 ms). At modest flood rates (e.g., 200 req/s from a single host), this can:
- Saturate PostgreSQL's `max_connections` (default 100), causing `FATAL: sorry, too many clients already` for legitimate application queries
- Force PostgreSQL's `postmaster` to fork/reap backend processes continuously, increasing background CPU
- Degrade query latency for the main application DB pool (`rosetta/app/db/db.go` uses a shared `gorm`/`sql.DB` pool that competes for the same `max_connections` budget) [7](#0-6) 

Impact is griefing-class: no direct economic loss, but service degradation for all users of the Rosetta API.

### Likelihood Explanation
- **No privileges required**: the endpoint is unauthenticated and reachable on the same port as the Rosetta API
- **Trivially scriptable**: `while true; do curl -s http://<host>/health/readiness; done` is sufficient
- **No exploit complexity**: attacker needs only network access to the pod/service port
- **Repeatable indefinitely**: no backoff, lockout, or circuit breaker protects the endpoint

### Recommendation
1. **Reuse a persistent connection** for the health check instead of opening/closing per request. Replace `postgres.New(postgres.Config{DSN: ...})` with a custom check that calls `db.PingContext(ctx)` on the existing shared `*sql.DB` pool already managed by `rosetta/app/db/db.go`.
2. **Apply rate limiting** to `/health/readiness` at the ingress level (add it to the Traefik middleware chain) or add an in-process token-bucket limiter in the handler.
3. **Restrict network access**: expose `/health/readiness` only to the Kubernetes kubelet CIDR (via `NetworkPolicy`) rather than to all external traffic.

### Proof of Concept
```bash
# Flood the readiness endpoint from an external host with network access to the pod port
# (default port 5700 per rosetta config)
for i in $(seq 1 500); do
  curl -s http://<rosetta-host>:5700/health/readiness &
done
wait

# On the PostgreSQL host, observe connection churn:
watch -n1 "psql -c \"SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE '%postgres%';\""

# Expected: connection count spikes repeatedly, legitimate queries begin returning:
# ERROR: sorry, too many clients already
```

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

**File:** charts/hedera-mirror-rosetta/values.yaml (L119-134)
```yaml
ingress:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: '{{ include "hedera-mirror-rosetta.namespace" . }}-{{ include "hedera-mirror-rosetta.fullname" . }}@kubernetescrd'
  enabled: true
  hosts:
    - host: ""
      paths:
        - "/rosetta/account"
        - "/rosetta/block"
        - "/rosetta/call"
        - "/rosetta/construction"
        - "/rosetta/events"
        - "/rosetta/mempool"
        - "/rosetta/network"
        - "/rosetta/search"
  tls:
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```

**File:** rosetta/main.go (L217-227)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** rosetta/app/db/db.go (L17-35)
```go
func ConnectToDb(dbConfig config.Db) interfaces.DbClient {
	db, err := gorm.Open(postgres.Open(dbConfig.GetDsn()), &gorm.Config{Logger: gormlogrus.New()})
	if err != nil {
		log.Warn(err)
	} else {
		log.Info("Successfully connected to database")
	}

	sqlDb, err := db.DB()
	if err != nil {
		log.Errorf("Failed to get sql DB: %s", err)
		return nil
	}

	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)

	return NewDbClient(db, dbConfig.StatementTimeout)
```
