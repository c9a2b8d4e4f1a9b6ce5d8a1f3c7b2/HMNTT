### Title
Unauthenticated `/health/readiness` Endpoint Enables Infrastructure Fingerprinting via Component Names and Error Message Leakage

### Summary
The `/health/readiness` endpoint in `rosetta/app/middleware/health.go` is registered with no authentication and returns a JSON body that always exposes hardcoded component names (`"postgresql"`, `"network"`), confirming the database technology. When checks fail, the `hellofresh/health-go/v4` library propagates the raw Go driver error string (which includes internal host, port, and username from the DSN) into the HTTP response body's `output` field, accessible to any unauthenticated external caller.

### Finding Description
**Code path:**

In `NewHealthController` (lines 37–50), two readiness checks are registered with hardcoded names:

```go
{Name: "postgresql", ..., Check: postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()})},
{Name: "network",    ..., Check: checkNetworkStatus(rosettaConfig.Port)},
```

`GetDsn()` (`rosetta/app/config/types.go`, lines 49–58) builds:
```
host=<HOST> port=<PORT> user=<USER> dbname=<DBNAME> password=<PASS> sslmode=disable
```

In `Routes()` (lines 63–78), both endpoints are registered with zero authentication:
```go
{"readiness", "GET", readinessPath, c.readinessHealth.HandlerFunc},
```

The `hellofresh/health-go/v4` library's `HandlerFunc` serializes each component's check result into a JSON `checks` map. When a check fails, the raw `error.Error()` string from the Go `lib/pq`/`pgx` driver is placed in the `output` field of the component's JSON entry. A typical failed-connection error from the postgres driver reads:

```
dial tcp 10.0.0.5:5432: connect: connection refused
```

or, on auth failure:

```
pq: password authentication failed for user "mirror_user"
```

Both reveal internal host, port, and username. The component name `"postgresql"` is always present regardless of check outcome, confirming the database technology unconditionally.

**Root cause:** No authentication or IP-restriction middleware is applied to the health routes, and raw driver error strings are forwarded verbatim into the public HTTP response body.

**Why existing checks fail:** There are no existing checks. The `Routes()` function registers the handler directly with no wrapping middleware. The `SkipOnErr: false` setting ensures failures are always reported (not silently swallowed), maximizing leakage.

### Impact Explanation
An unauthenticated attacker learns: (1) the database technology is PostgreSQL (always, from the component name), (2) the internal database host IP and port (from connection-failure error messages), (3) the database username (from authentication-failure error messages), and (4) the internal Rosetta service port (from the `"network"` check error). This information directly supports targeted lateral movement, credential-stuffing against the database port, and network topology mapping — all without any credentials.

### Likelihood Explanation
The endpoint requires only a single unauthenticated HTTP GET request. No special tooling, timing, or privilege is needed. The Rosetta API port is typically exposed to allow blockchain clients to connect, making the health sub-paths reachable from the internet in common deployments. The attack is trivially repeatable and leaves minimal forensic trace.

### Recommendation
1. **Restrict access**: Place the `/health/readiness` endpoint behind a network policy or reverse-proxy rule that allows only internal orchestration systems (e.g., Kubernetes kubelet CIDR) to reach it.
2. **Sanitize error output**: Wrap the postgres check so that on failure it returns a generic sentinel error (e.g., `errors.New("database unavailable")`) rather than the raw driver error, preventing DSN-derived details from reaching the response body.
3. **Avoid technology-identifying names**: Replace `"postgresql"` with a generic name such as `"db"` to prevent passive fingerprinting even on successful responses.

### Proof of Concept
```bash
# Step 1: Hit the endpoint with no credentials
curl -s http://<rosetta-host>:<port>/health/readiness | jq .

# Expected response when DB is unreachable (reveals internal host/port):
{
  "status": "unavailable",
  "checks": {
    "postgresql": {
      "status": "unavailable",
      "output": "dial tcp 10.0.0.5:5432: connect: connection refused",
      "timestamp": "..."
    },
    "network": { ... }
  }
}

# Step 2: Even when healthy, component names confirm DB technology:
{
  "status": "ok",
  "checks": {
    "postgresql": {"status": "ok"},
    "network":    {"status": "ok"}
  }
}
```

Both responses are returned to any caller with zero authentication. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rosetta/app/config/types.go (L49-58)
```go
func (db Db) GetDsn() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
		db.Host,
		db.Port,
		db.Username,
		db.Name,
		db.Password,
	)
}
```
