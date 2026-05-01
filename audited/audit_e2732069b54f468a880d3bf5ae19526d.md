### Title
Unauthenticated, Unthrottled `/health/readiness` Endpoint Triggers Unbounded PostgreSQL Connections Per Request

### Summary
The `/health/readiness` endpoint in `rosetta/app/middleware/health.go` is registered with no authentication, no rate limiting, and no result caching. Every inbound HTTP request unconditionally invokes the `hellofresh/health-go` postgres check, which opens a fresh database connection and executes a query. In any deployment where port 5700 is reachable by external clients (Docker Compose exposes it directly; Kubernetes operators may change `service.type` from `ClusterIP`), an unprivileged attacker can flood this endpoint to exhaust PostgreSQL connections and degrade all database-dependent operations.

### Finding Description
**Code location:** `rosetta/app/middleware/health.go`, `NewHealthController()` lines 37–52 and `Routes()` lines 63–78.

```go
// Lines 37-42: postgres check registered with no cache TTL
readinessChecks := []health.Config{
    {
        Name:      "postgresql",
        Timeout:   time.Second * 10,
        SkipOnErr: false,
        Check:     postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),
    },
```

```go
// Lines 74-76: route registered with no middleware
{
    "readiness", "GET", readinessPath,
    c.readinessHealth.HandlerFunc,
},
```

`health.New(health.WithChecks(...))` is called **without** `health.WithCacheDuration()`, so the `hellofresh/health-go` library re-executes every registered check synchronously on each HTTP request. The `postgres.New()` check opens a new `sql.DB`, calls `Ping()`, and closes it — one new PostgreSQL connection per HTTP request.

**Why existing controls fail:**
The Traefik `rateLimit` middleware (average: 10 req/s) is attached only to the ingress, which exposes exclusively `/rosetta/account`, `/rosetta/block`, etc. — the `/health/readiness` path is absent from `ingress.hosts[].paths`. The Go HTTP server (`rosetta/main.go` lines 217–227) applies only `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — none of which throttle or authenticate requests. The `docker-compose.yml` (line 151) binds `5700:5700` to all interfaces, making the full server — including `/health/readiness` — reachable by any external client.

### Impact Explanation
Each request to `/health/readiness` causes PostgreSQL to:
- Accept a new TCP connection
- Authenticate the client
- Execute a ping/query
- Tear down the connection

At high request rates this exhausts `max_connections`, starves the connection pool used by legitimate Rosetta API handlers, and generates WAL activity from connection state changes. All database-dependent operations (block queries, account lookups, transaction retrieval) degrade or fail. The impact is griefing/DoS with no economic damage to network participants, consistent with the Medium severity classification.

### Likelihood Explanation
Precondition: the attacker can reach port 5700. This is satisfied by default in Docker Compose deployments (port bound to `0.0.0.0:5700`). In Kubernetes, the default `ClusterIP` service type limits direct external access, but operators commonly change `service.type` to `NodePort` or `LoadBalancer`, or the GCP gateway `maxRatePerEndpoint: 250` applies only to `/rosetta` prefix paths. No credentials, tokens, or special knowledge are required — a single `curl` loop suffices.

### Recommendation
1. **Add a cache TTL** to the health check so repeated requests do not re-query PostgreSQL:
   ```go
   readinessHealth, err := health.New(
       health.WithChecks(readinessChecks...),
       health.WithCacheDuration(5 * time.Second),
   )
   ```
2. **Apply rate limiting at the application layer** (e.g., `golang.org/x/time/rate` token bucket) in the `Routes()` handler for `/health/readiness`, independent of ingress configuration.
3. **Restrict network exposure**: add the health paths to a separate, cluster-internal port or use Kubernetes `NetworkPolicy` to block external access to port 5700 for non-probe sources.
4. In Docker Compose, bind port 5700 to `127.0.0.1` only.

### Proof of Concept
```bash
# Docker Compose deployment — no credentials required
while true; do
  curl -s http://<host>:5700/health/readiness -o /dev/null &
done
# Or with parallelism:
seq 1 500 | xargs -P 500 -I{} curl -s http://<host>:5700/health/readiness -o /dev/null

# Observe on PostgreSQL:
# SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE '%health%';
# Watch max_connections approached; legitimate queries begin timing out.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rosetta/app/middleware/health.go (L37-52)
```go
	readinessChecks := []health.Config{
		{
			Name:      "postgresql",
			Timeout:   time.Second * 10,
			SkipOnErr: false,
			Check:     postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),
		},
		{
			Name:      "network",
			Timeout:   time.Second * 10,
			SkipOnErr: false,
			Check:     checkNetworkStatus(rosettaConfig.Port),
		},
	}
	readinessHealth, err := health.New(health.WithChecks(readinessChecks...))
	if err != nil {
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L119-133)
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

**File:** docker-compose.yml (L137-153)
```yaml
  rosetta:
    configs:
      - source: app-config
        target: /usr/etc/hiero/application.yml
        uid: "1000"
        gid: "1000"
    deploy:
      replicas: 0
    environment:
      HIERO_MIRROR_ROSETTA_API_CONFIG: /usr/etc/hiero/application.yml
      HIERO_MIRROR_ROSETTA_DB_HOST: db
    image: gcr.io/mirrornode/hedera-mirror-rosetta:0.154.0-SNAPSHOT
    pull_policy: always
    ports:
      - 5700:5700
    restart: unless-stopped
    tty: true
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
