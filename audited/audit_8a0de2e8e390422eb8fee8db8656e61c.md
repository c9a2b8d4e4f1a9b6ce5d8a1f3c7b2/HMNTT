### Title
Absence of Application-Level Rate Limiting on `/network/status` Enables DB Connection Pool Exhaustion via Distributed Clients

### Summary
The `NetworkStatus()` handler in `rosetta/app/services/network_service.go` issues three synchronous database queries per request with no application-level rate limiting or concurrency cap. The only throttling controls exist at the Traefik ingress layer, which is optional, infrastructure-dependent, and uses per-IP in-flight limiting that is trivially bypassed by distributed clients. An unprivileged attacker controlling 20+ source IPs can exhaust the 100-connection DB pool, rendering the Rosetta service unavailable.

### Finding Description

**Exact code path:**

`NetworkStatus()` (lines 59–88, `rosetta/app/services/network_service.go`) issues three blocking DB calls per invocation:
- `n.RetrieveGenesis(ctx)` → `blockRepo.RetrieveGenesis` → DB query
- `n.RetrieveLatest(ctx)` → `blockRepo.RetrieveLatest` → DB query
- `n.addressBookEntryRepo.Entries(ctx)` → DB query [1](#0-0) 

**Application-level middleware chain** (`rosetta/main.go`, lines 217–219) applies only `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware`. There is no rate limiting, no concurrency cap, and no per-IP throttle at the application layer. [2](#0-1) 

**DB connection pool** is configured via `rosetta/app/db/db.go` (lines 31–33) using values from `config.Pool`. The documented default is `maxOpenConnections: 100`. [3](#0-2) [4](#0-3) 

**The only throttling controls** are in the Traefik Helm chart values (`charts/hedera-mirror-rosetta/values.yaml`, lines 149–166):
- `inFlightReq: amount: 5` with `sourceCriterion: ipStrategy: depth: 1` — limits 5 concurrent requests **per source IP**
- `rateLimit: average: 10` with `sourceCriterion: requestHost: true` — limits 10 req/s **globally per hostname** (not per IP) [5](#0-4) 

**Root cause and failed assumptions:**

1. The `inFlightReq` per-IP limit (5 concurrent/IP) is bypassed by using ≥20 distinct source IPs. With 20 IPs × 5 concurrent = 100 simultaneous connections, the entire pool is occupied.
2. The `rateLimit: requestHost: true` is a global (not per-IP) limit of 10 req/s. It does not prevent distributed clients from collectively holding 100 long-lived connections once established.
3. Both controls are **Traefik-only** — they are absent in any non-Kubernetes deployment (Docker Compose, bare-metal, direct port exposure). The application binary itself has zero rate limiting.
4. The `retry: attempts: 3` middleware amplifies load: each forwarded request can trigger up to 4 upstream calls, multiplying DB pressure. [6](#0-5) 

### Impact Explanation

When the 100-connection pool is exhausted, all subsequent `NetworkStatus()` (and any other DB-backed endpoint) calls block waiting for a free connection. The `statementTimeout` of 20 seconds means connections are held for up to 20 seconds before release, during which new attacker requests immediately reclaim them. The Rosetta service becomes fully unresponsive to legitimate callers. Because the DB pool is shared across all endpoints served by the same `dbClient` instance, block queries, account queries, and construction queries are also starved. In a single-replica deployment this is a complete service outage; in a multi-replica deployment the impact scales with the number of replicas the attacker can target simultaneously. [7](#0-6) [8](#0-7) 

### Likelihood Explanation

The attack requires no authentication, no special protocol knowledge beyond a standard Rosetta POST body, and no privileged network position. The `/network/status` endpoint is publicly documented and tested. Obtaining 20 source IPs is trivial (cloud VMs, residential proxies, botnets). The attack is repeatable and stateless — each request is independent. In non-Kubernetes deployments (the common developer/operator path), there is zero infrastructure-level mitigation.

### Recommendation

1. **Application-level concurrency cap**: Add an `http.MaxBytesReader` and a semaphore-based middleware in `rosetta/main.go` that limits total in-flight DB-backed requests (e.g., 50) regardless of source IP, returning HTTP 429 when the cap is reached.
2. **Per-IP rate limiting in the application**: Integrate a token-bucket middleware (e.g., `golang.org/x/time/rate` with a per-IP map) directly in the Go HTTP handler chain, so protection is present regardless of ingress configuration.
3. **Fix Traefik `rateLimit` source criterion**: Change `sourceCriterion` from `requestHost: true` to `ipStrategy: depth: 1` so the rate limit is enforced per client IP, not globally per hostname.
4. **Reduce `maxOpenConnections`**: Set a lower ceiling (e.g., 20–30) and rely on PgBouncer for pooling, so pool exhaustion has a smaller blast radius.
5. **Remove the `retry` middleware** or scope it only to network errors, not to upstream 5xx responses, to prevent retry amplification.

### Proof of Concept

**Preconditions**: Rosetta service reachable at `http://<host>:5700` (direct) or via Traefik ingress. 20 distinct source IPs available (e.g., cloud VMs or proxies).

**Steps**:

```bash
# On each of 20 distinct source IPs, run concurrently:
for i in $(seq 1 5); do
  curl -s -X POST http://<host>:5700/network/status \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
done
wait
```

**Result**: 20 IPs × 5 concurrent = 100 simultaneous requests, each holding a DB connection for up to 20 seconds (`statementTimeout`). The pool reaches `maxOpenConnections=100`. All subsequent legitimate requests to any DB-backed endpoint receive connection-wait timeouts or errors. The Rosetta service stops responding to `/network/status`, `/block`, and `/account/balance` until the attacker releases connections.

### Citations

**File:** rosetta/app/services/network_service.go (L59-88)
```go
func (n *networkAPIService) NetworkStatus(
	ctx context.Context,
	_ *rTypes.NetworkRequest,
) (*rTypes.NetworkStatusResponse, *rTypes.Error) {
	if !n.IsOnline() {
		return nil, errors.ErrEndpointNotSupportedInOfflineMode
	}

	genesisBlock, err := n.RetrieveGenesis(ctx)
	if err != nil {
		return nil, err
	}

	currentBlock, err := n.RetrieveLatest(ctx)
	if err != nil {
		return nil, err
	}

	peers, err := n.addressBookEntryRepo.Entries(ctx)
	if err != nil {
		return nil, err
	}

	return &rTypes.NetworkStatusResponse{
		CurrentBlockIdentifier: currentBlock.GetRosettaBlockIdentifier(),
		CurrentBlockTimestamp:  currentBlock.GetTimestampMillis(),
		GenesisBlockIdentifier: genesisBlock.GetRosettaBlockIdentifier(),
		Peers:                  peers.ToRosetta(),
	}, nil
}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** rosetta/app/db/db.go (L31-33)
```go
	sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
	sqlDb.SetConnMaxLifetime(time.Duration(dbConfig.Pool.MaxLifetime) * time.Minute)
	sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```

**File:** docs/configuration.md (L656-658)
```markdown
| `hiero.mirror.rosetta.db.pool.maxIdleConnections` | 20                  | The maximum number of idle database connections                                                     |
| `hiero.mirror.rosetta.db.pool.maxLifetime`        | 30                  | The maximum lifetime of a database connection in minutes                                            |
| `hiero.mirror.rosetta.db.pool.maxOpenConnections` | 100                 | The maximum number of open database connections                                                     |
```

**File:** docs/configuration.md (L660-660)
```markdown
| `hiero.mirror.rosetta.db.statementTimeout`        | 20                  | The number of seconds to wait before timing out a query statement                                   |
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

**File:** rosetta/app/config/types.go (L77-81)
```go
type Pool struct {
	MaxIdleConnections int `yaml:"maxIdleConnections"`
	MaxLifetime        int `yaml:"maxLifetime"`
	MaxOpenConnections int `yaml:"maxOpenConnections"`
}
```
