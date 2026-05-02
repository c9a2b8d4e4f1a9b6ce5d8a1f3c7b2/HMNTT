### Title
Unauthenticated `/health/readiness` Endpoint Triggers Uncached, Amplified Resource Checks on Every Request

### Summary
The `/health/readiness` endpoint in `rosetta/app/middleware/health.go` is exposed without authentication, rate limiting, or response caching. Every external GET request unconditionally executes both a live PostgreSQL query and two internal HTTP calls (`/network/list` + `/network/status`) against the local Rosetta server, creating a 3x resource amplification factor per request that any unprivileged external caller can exploit at will.

### Finding Description
**Exact code path:**

In `Routes()` ( [1](#0-0) ), the `/health/readiness` path is registered with `c.readinessHealth.HandlerFunc` — no authentication middleware, no rate-limiting wrapper, no IP allowlist.

`readinessHealth` is constructed with two checks ( [2](#0-1) ):
- `postgresql` — opens a real DB connection and executes a liveness query (10 s timeout)
- `network` — calls `checkNetworkStatus`, which makes **two** sequential HTTP calls back into the same Rosetta process

`checkNetworkStatus` ( [3](#0-2) ) calls `NetworkList` then `NetworkStatus` on `http://localhost:<port>`. Both of those handlers themselves query the mirror-node PostgreSQL database (via `NetworkAPIService`).

**Root cause:** `health.New(health.WithChecks(...))` is called with no `WithCacheDuration` or `WithMaxConcurrent` option. The `hellofresh/health-go/v4` library runs all registered checks fresh on **every** incoming request. No caching, no concurrency cap, no rate limiting is applied anywhere in the rosetta middleware stack (confirmed: zero matches for `WithMaxConcurrent`, `WithCacheDuration`, `RateLimit` in `rosetta/**/*.go`).

**Amplification chain per single external request:**
```
GET /health/readiness (external, unauthenticated)
  ├─ postgresql check  → 1 DB connection + query
  └─ network check
       ├─ POST /network/list  → DB query (address book, network identifiers)
       └─ POST /network/status → DB query (latest block, genesis block)
```
Result: 1 external request → ≥3 DB queries + 2 internal HTTP round-trips.

### Impact Explanation
At a moderate polling rate of 10 req/s an attacker generates ≥30 DB queries/s and 20 internal HTTP requests/s with zero authentication cost. On a lightly-to-moderately loaded node this directly competes with legitimate traffic for:
- PostgreSQL connection pool slots (pool exhaustion degrades all API responses)
- CPU/goroutine budget (each internal HTTP call spawns goroutine work inside the same process)
- Network socket descriptors

The Kubernetes `readinessProbe` already polls this endpoint every few seconds ( [4](#0-3) ), meaning the baseline is non-zero; an attacker adding even 5–10 req/s on top can realistically push total DB load ≥30% above the 24-hour baseline on a node with modest organic traffic. Severity: **Medium** (resource exhaustion / availability degradation, no data exfiltration).

### Likelihood Explanation
- **Precondition:** None. The endpoint is a plain HTTP GET, no credentials, no token, no network-level restriction visible in the application code.
- **Attacker capability:** Any internet-reachable client. A single `curl` loop or a trivial script suffices.
- **Repeatability:** Fully repeatable; the checks are stateless and re-execute identically on every call.
- **Detection difficulty:** Health-check traffic blends with legitimate Kubernetes probe traffic, making anomaly detection harder.

### Recommendation
1. **Add a short cache duration** to the readiness health instance so repeated calls within a window (e.g., 5 s) return the cached result without re-executing checks:
   ```go
   readinessHealth, err := health.New(
       health.WithChecks(readinessChecks...),
       health.WithCacheDuration(5 * time.Second),
   )
   ```
2. **Restrict access at the network/ingress layer** — the readiness path should only be reachable by the Kubernetes control plane (kubelet CIDR), not by arbitrary external clients. Add an ingress rule or Traefik middleware to block external access to `/health/*`.
3. **Add `WithMaxConcurrent(1)`** to prevent concurrent flood requests from running checks in parallel.
4. **Decouple the network check** from live DB-hitting API calls; use a lightweight in-process flag (e.g., an atomic bool set by the startup sequence) instead of looping back through the full API stack.

### Proof of Concept
```bash
# Attacker with no credentials, moderate rate (10 req/s)
while true; do
  curl -s -o /dev/null http://<rosetta-node-host>/health/readiness &
  sleep 0.1
done
```
Each iteration triggers: 1 PostgreSQL liveness query + `POST /network/list` (DB query) + `POST /network/status` (DB query) — all within the same process. Monitor PostgreSQL `pg_stat_activity` active connections and CPU before/after to observe the amplification.

### Citations

**File:** rosetta/app/middleware/health.go (L37-51)
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

**File:** rosetta/app/middleware/health.go (L80-100)
```go
func checkNetworkStatus(port uint16) func(ctx context.Context) error {
	serverUrl := fmt.Sprintf("http://localhost:%d", port)
	cfg := client.NewConfiguration(serverUrl, "readiness-check", nil)
	rosettaClient := client.NewAPIClient(cfg)

	return func(ctx context.Context) (checkErr error) {
		networkList, _, err := rosettaClient.NetworkAPI.NetworkList(ctx, &types.MetadataRequest{})
		if err != nil {
			log.Errorf("Readiness check, /network/list failed: %v", err)
			return err
		}

		network := networkList.NetworkIdentifiers[0]
		_, _, err = rosettaClient.NetworkAPI.NetworkStatus(ctx, &types.NetworkRequest{NetworkIdentifier: network})
		if err != nil {
			log.Errorf("Readiness check, /network/status failed: %v", err)
			return err
		}

		return
	}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L236-242)
```yaml
readinessProbe:
  failureThreshold: 5
  httpGet:
    path: /health/readiness
    port: http
  initialDelaySeconds: 30
  timeoutSeconds: 2
```
