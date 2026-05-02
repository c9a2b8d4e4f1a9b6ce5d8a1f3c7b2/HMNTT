### Title
Unauthenticated Internal Service State Enumeration via `GET /health/readiness`

### Summary
The `GET /health/readiness` endpoint in `rosetta/app/middleware/health.go` is registered with no authentication and returns a structured JSON response from the `hellofresh/health-go/v4` library that includes per-component health status for named internal dependencies (`postgresql`, `network`). When checks fail, the library propagates the raw Go error string into the response body, which for the postgres driver typically includes the internal host address and port (e.g., `dial tcp 10.0.0.5:5432: connect: connection refused`). Any unprivileged external user can repeatedly poll this endpoint to map which internal components are reachable and infer network partition state.

### Finding Description
**Code path:**
- `rosetta/app/middleware/health.go`, `Routes()`, lines 63–78: registers `GET /health/readiness` with `c.readinessHealth.HandlerFunc` directly, no auth wrapper.
- `rosetta/app/middleware/health.go`, `NewHealthController()`, lines 37–50: two named checks are registered — `"postgresql"` (using `postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()})`) and `"network"` (using `checkNetworkStatus(rosettaConfig.Port)`).
- `rosetta/main.go`, lines 217–219: the only middleware applied to the router is `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — no authentication middleware exists anywhere in the chain for the rosetta server.

**Root cause:** The failed assumption is that health endpoints are internal-only. In practice, the rosetta server binds on `0.0.0.0:<port>` (line 221 of `rosetta/main.go`) and the health routes are served on the same port as all other API routes with no network-level or application-level access control. The `hellofresh/health-go/v4` `HandlerFunc` serializes the `health.Check` struct — which includes a `Checks` map keyed by component name and containing each component's `Status`, `Timestamp`, and `Error` string — directly into the HTTP response body.

**Exploit flow:**
1. Attacker sends `GET /health/readiness` with no credentials.
2. The handler runs the postgres DSN connection check and the internal `NetworkList`/`NetworkStatus` Rosetta API check.
3. If either check fails, the raw Go error (e.g., `dial tcp <internal-db-host>:<port>: connect: connection refused`) is included in the JSON `checks.postgresql.error` field.
4. The attacker receives a JSON body enumerating which of `postgresql` and `network` are up or down, with error strings that may contain internal hostnames/IPs and ports.

**Why existing checks fail:** There are no existing checks. The `CorsMiddleware` only controls cross-origin browser behavior and does not restrict direct HTTP clients. No IP allowlist, no token, no mTLS is applied to this route.

### Impact Explanation
An attacker gains real-time visibility into the internal connectivity state of the rosetta service: whether its PostgreSQL backend is reachable (and from error messages, its internal address), and whether the rosetta API itself is functional. This constitutes infrastructure reconnaissance that can be used to time attacks (e.g., exploit during a DB failover window), confirm successful network partitioning after a prior attack, or identify internal IP ranges and port assignments. Severity is **Medium** — it is information disclosure, not direct code execution, but the disclosed data is operationally sensitive.

### Likelihood Explanation
Exploitation requires only an HTTP client and knowledge of the service's public address and port — no credentials, no special tooling, no prior access. The endpoint is stable, deterministic, and can be polled continuously. Any internet-exposed deployment is trivially exploitable. Likelihood is **High**.

### Recommendation
1. **Restrict network access**: Serve the health endpoints on a separate, non-public port (e.g., a management port bound to `127.0.0.1` or a private network interface only), separate from the main Rosetta API port.
2. **Suppress error details in responses**: Configure the `hellofresh/health-go` checks to not propagate raw error strings to the HTTP response body. Use a custom check wrapper that logs the error server-side but returns only a generic failure status to the caller.
3. **Add authentication or IP allowlisting**: If the health endpoint must remain on the public port, gate it behind at minimum an IP allowlist (e.g., only Kubernetes node CIDR ranges for liveness/readiness probes).

### Proof of Concept
```bash
# No credentials required. Works from any network with access to the rosetta port.
curl -s http://<rosetta-host>:<port>/health/readiness | jq .

# Example response when DB is unreachable:
# {
#   "status": "unavailable",
#   "timestamp": "2024-01-01T00:00:00Z",
#   "checks": {
#     "postgresql": {
#       "status": "unavailable",
#       "timestamp": "2024-01-01T00:00:00Z",
#       "error": "dial tcp 10.0.1.23:5432: connect: connection refused"
#     },
#     "network": {
#       "status": "ok",
#       "timestamp": "2024-01-01T00:00:00Z"
#     }
#   }
# }
# Attacker learns: DB is at 10.0.1.23:5432, network/rosetta API is up.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/health.go (L37-50)
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

**File:** rosetta/main.go (L217-221)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
```
