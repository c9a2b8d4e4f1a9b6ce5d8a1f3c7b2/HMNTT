### Title
Unauthenticated Per-IP Rate Limiting Absent on `/network/status` Enables Single-Source Request Flood DoS

### Summary
`NetworkStatus()` in `rosetta/app/services/network_service.go` executes three database queries per request with no authentication, no application-level rate limiting, and no per-IP concurrency cap. The only rate-limiting controls that exist are Traefik middleware definitions in the Helm chart, but they are gated behind `global.middleware: false` by default and are therefore not deployed in a standard installation. Any unauthenticated attacker from a single IP can flood the endpoint, exhausting the database connection pool and denying service to legitimate users.

### Finding Description

**Exact code path:**

`NetworkStatus()` at `rosetta/app/services/network_service.go` lines 59–88 performs three sequential database operations on every call:
- `n.RetrieveGenesis(ctx)` → SQL query against `record_file` + `account_balance` tables
- `n.RetrieveLatest(ctx)` → SQL query `selectLatestWithIndex` against `record_file`
- `n.addressBookEntryRepo.Entries(ctx)` → two SQL queries against `address_book_entry` + `address_book_service_endpoint`

The only guard is `n.IsOnline()` (line 63), which rejects requests in offline mode only — it is not a rate limit.

**Middleware chain in `main.go` (lines 217–219):**
```go
metricsMiddleware := middleware.MetricsMiddleware(router)
tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
No rate-limiting or concurrency-limiting middleware is applied at the application layer.

**Infrastructure-level controls are opt-in and disabled by default:**

`charts/hedera-mirror-rosetta/templates/middleware.yaml` line 3:
```
{{ if and .Values.global.middleware .Values.middleware -}}
```
`charts/hedera-mirror-rosetta/values.yaml` line 95:
```yaml
global:
  middleware: false
```
The Traefik `rateLimit` (10 req/s per host) and `inFlightReq` (5 concurrent per IP) middleware objects are **never rendered** unless an operator explicitly sets `global.middleware: true`. In a default Helm deployment they do not exist.

### Impact Explanation
Each `/network/status` request drives 3–4 database round-trips. A single attacker IP sending requests at high frequency (e.g., 500 req/s, trivially achievable with `wrk` or `hey`) will saturate the GORM/pgx connection pool. Once the pool is exhausted, all other Rosetta endpoints that share the same `dbClient` (block queries, account queries, construction) will queue or time out, making the node completely unresponsive to legitimate Rosetta consumers (exchanges, indexers, validators). Because the Rosetta spec requires no authentication on data-read endpoints, there is no credential barrier to raise the cost of the attack.

### Likelihood Explanation
The precondition is zero: no account, no token, no prior knowledge beyond the server's IP and port. The endpoint is publicly documented as part of the Rosetta API spec. Any script kiddie with `curl` in a loop or a load-testing tool can trigger this. The attack is repeatable indefinitely and requires no state. Deployments that follow the default Helm values (the majority) have no mitigation in place.

### Recommendation
1. **Application-level rate limiting (primary fix):** Add a per-IP token-bucket middleware in `rosetta/main.go` using `golang.org/x/time/rate` or `github.com/ulule/limiter`, applied before the router, so it is enforced regardless of infrastructure configuration.
2. **Enable middleware by default:** Change `global.middleware` default to `true` in `charts/hedera-mirror-rosetta/values.yaml` so the Traefik `inFlightReq` and `rateLimit` controls are active in all standard deployments.
3. **Cache `Entries()` results:** The address book changes infrequently; caching the result with a short TTL (e.g., 30 s) would dramatically reduce per-request DB cost and blunt the amplification effect.
4. **Set a DB query timeout:** Ensure `GetDbWithContext` uses a short deadline so flooded requests fail fast rather than holding connections.

### Proof of Concept
```bash
# Prerequisites: rosetta node running at localhost:5700 in online mode,
# default Helm values (global.middleware: false)

# Step 1 – confirm endpoint is open with no auth
curl -s -X POST http://localhost:5700/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'
# Expect: 200 with CurrentBlockIdentifier

# Step 2 – flood from a single IP (requires `hey` tool)
hey -n 100000 -c 200 -m POST \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  http://localhost:5700/network/status &

# Step 3 – simultaneously probe a different endpoint
curl -s -X POST http://localhost:5700/network/list \
  -H 'Content-Type: application/json' \
  -d '{}'
# Result: request hangs or returns 500/timeout due to exhausted DB pool
# while the flood is running — demonstrating denial of service to
# legitimate users with no authentication required from the attacker.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L95-95)
```yaml
  middleware: false
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
