### Title
Unauthenticated `/health/readiness` Endpoint Leaks Per-Component Failure Details and Internal Infrastructure Topology

### Summary
The `/health/readiness` endpoint in `rosetta/app/middleware/health.go` is registered with no authentication or access control and delegates directly to the `hellofresh/health-go/v4` `HandlerFunc`, which serializes a full `health.Check` JSON body containing named per-component check results (`"postgresql"`, `"network"`) and their raw error `output` strings. Any unprivileged external user can poll this endpoint to determine which specific infrastructure component is degraded and extract internal hostnames, IPs, and ports from driver-level error messages embedded in the response.

### Finding Description
**Code path:**

- `rosetta/app/middleware/health.go`, `NewHealthController()`, lines 37–50: two checks are registered with hardcoded names `"postgresql"` and `"network"`.
- `rosetta/app/middleware/health.go`, `Routes()`, lines 63–78: both routes are registered with zero authentication — the handler is `c.readinessHealth.HandlerFunc` directly.
- `rosetta/main.go`, lines 217–219: the only middleware chain applied is `MetricsMiddleware → TracingMiddleware → CorsMiddleware`. None of these restrict access.
- `rosetta/app/middleware/trace.go`, line 19: `internalPaths` marks `/health/readiness` as "internal" but this **only** changes the log level from `Info` to `Debug` — it provides zero access control.

**Root cause:**

The `hellofresh/health-go/v4` `HandlerFunc` serializes a `health.Check` struct to JSON with the following structure when any check fails:

```json
{
  "status": "unavailable",
  "checks": {
    "postgresql": {
      "status": "unavailable",
      "output": "dial tcp 10.0.1.42:5432: connect: connection refused",
      "timestamp": "2024-01-01T00:00:00Z"
    },
    "network": {
      "status": "ok",
      "timestamp": "2024-01-01T00:00:00Z"
    }
  }
}
```

The `output` field is the raw `error.Error()` string from the Go postgres driver or network client — it routinely includes internal hostnames, IP addresses, and port numbers. The failed assumption is that health endpoints are only reachable by internal Kubernetes probes; the Rosetta API is designed to be publicly accessible per the Rosetta API specification, and no network-level restriction is enforced in code.

**Exploit flow:**

1. Attacker sends `GET /health/readiness` to the public Rosetta port — no credentials, no special headers required.
2. If PostgreSQL is unreachable, the response body contains `"postgresql": {"status": "unavailable", "output": "dial tcp <internal-db-host>:<port>: ..."}`, revealing the internal DB host and port.
3. If the network check fails, the `"network"` entry is marked `"unavailable"`, confirming the Rosetta network layer (L1 connectivity) is the weak point.
4. By polling repeatedly, the attacker can map which component degrades under load or during maintenance windows, building a precise picture of the infrastructure topology.

### Impact Explanation
An attacker gains:
- Confirmation that the infrastructure uses PostgreSQL (component name exposed verbatim).
- Identification of which specific layer (DB vs. network/L1) is the current failure point.
- Internal hostnames, IP addresses, and port numbers from raw driver error strings in the `output` field.

This intelligence directly supports targeted attacks against the L1 network components (e.g., the Hedera consensus nodes or the PostgreSQL mirror DB) that underpin smart contract execution. While no funds are directly at risk from the disclosure alone, it materially lowers the cost of a subsequent targeted DoS or lateral movement attack against the identified components.

### Likelihood Explanation
Exploitation requires only network access to the Rosetta API port and a single unauthenticated HTTP GET request — no credentials, no special tooling, no prior knowledge. The Rosetta API is intended to be publicly reachable. The attack is trivially repeatable, automatable, and leaves minimal forensic trace (health endpoint requests are logged only at `Debug` level per `trace.go` line 55, meaning they are suppressed in default `Info`-level deployments).

### Recommendation
1. **Strip the response body on failure**: Replace `c.readinessHealth.HandlerFunc` with a thin wrapper that returns only `{"status":"ok"}` / `{"status":"unavailable"}` with HTTP 200/503, discarding the `checks` map entirely before writing the response.
2. **Alternatively, restrict access by source IP**: Apply a middleware that allows `/health/readiness` only from the cluster-internal CIDR (e.g., the Kubernetes pod network), rejecting all external requests with HTTP 403 before the handler runs.
3. **Sanitize error messages**: If per-check detail is required internally, ensure the `output` field is scrubbed of hostnames, IPs, and ports before serialization.

### Proof of Concept
```bash
# No authentication required. Replace <host>:<port> with the Rosetta API address.
curl -s http://<host>:<port>/health/readiness | jq .

# Example response when PostgreSQL is unreachable:
# {
#   "status": "unavailable",
#   "checks": {
#     "postgresql": {
#       "status": "unavailable",
#       "output": "dial tcp 10.0.1.42:5432: connect: connection refused",
#       "timestamp": "2024-05-01T12:00:00Z"
#     },
#     "network": {
#       "status": "ok",
#       "timestamp": "2024-05-01T12:00:00Z"
#     }
#   }
# }
# => Attacker now knows: DB is at 10.0.1.42:5432, network/L1 layer is healthy.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rosetta/app/middleware/trace.go (L19-19)
```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```

**File:** rosetta/app/middleware/trace.go (L55-59)
```go
		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
		}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
