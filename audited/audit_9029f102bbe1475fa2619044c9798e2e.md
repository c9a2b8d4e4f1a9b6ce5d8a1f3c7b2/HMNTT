### Title
Unauthenticated DoS via Connection Exhaustion on `NetworkStatus()` Due to Disabled Rate-Limiting Middleware

### Summary
The `NetworkStatus()` endpoint in `rosetta/app/services/network_service.go` issues three database queries per request with no application-level concurrency control. The Traefik-based rate-limiting and in-flight request middleware defined in the Helm chart is **disabled by default** (`global.middleware: false`), leaving the endpoint fully exposed to connection-pool exhaustion by any unprivileged external caller. When the pool is saturated, both `addressBookEntryRepo.Entries(ctx)` and `blockRepo.RetrieveLatest(ctx)` return errors, causing `NetworkStatus()` to return an error response that causes Rosetta clients to abort pre-submission network checks.

### Finding Description

**Exact code path:**

`rosetta/app/services/network_service.go`, `NetworkStatus()`, lines 59–88:
```
RetrieveGenesis(ctx)          → blockRepo DB query
RetrieveLatest(ctx)           → blockRepo DB query
addressBookEntryRepo.Entries(ctx) → complex multi-join aggregation query (×2 file IDs)
```

**Root cause — disabled middleware:**

`charts/hedera-mirror-rosetta/values.yaml` line 95:
```yaml
global:
  middleware: false   # ← rate-limiting middleware is OFF by default
```

The Traefik `Middleware` resource is only rendered when **both** `global.middleware` and `middleware` are truthy:
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```
(`charts/hedera-mirror-rosetta/templates/middleware.yaml`, line 3)

The `inFlightReq` (5 concurrent per IP) and `rateLimit` (10 req/s per host) rules defined in `values.yaml` lines 152–161 are therefore never applied in a default deployment.

**Application-level middleware chain** (`rosetta/main.go`, lines 217–219):
```go
metricsMiddleware := middleware.MetricsMiddleware(router)
tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
corsMiddleware    := server.CorsMiddleware(tracingMiddleware)
```
No rate-limiting or concurrency-limiting middleware is present in the Go application itself.

**DB connection pool** (`rosetta/app/db/db.go`, lines 31–33):
```go
sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)
sqlDb.SetConnMaxLifetime(...)
sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)
```
`MaxOpenConnections` is read from config. No default value is set in any application YAML (none found in the rosetta tree). When `MaxOpenConnections` is 0 (Go `database/sql` default), connections are unlimited and PostgreSQL's own `max_connections` becomes the ceiling. When it is set to a finite value, requests queue and time out under flood conditions.

**Only guard present** (`network_service.go`, line 63):
```go
if !n.IsOnline() {
    return nil, errors.ErrEndpointNotSupportedInOfflineMode
}
```
This is a mode check, not a rate or concurrency limit.

### Impact Explanation
Under a flood, all DB connections are consumed. `Entries()` returns `errors.ErrDatabaseError` and `RetrieveLatest()` returns an error; `NetworkStatus()` propagates these as Rosetta error responses. Rosetta clients (e.g., `rosetta-cli`, exchange integrations) call `/network/status` as a mandatory pre-flight check before submitting construction transactions. A sustained flood causes every such check to fail, effectively blocking all fund transfers routed through this Rosetta gateway for the duration of the attack. This is a **high-severity availability impact** on a financial-transaction pathway.

### Likelihood Explanation
- **No authentication required** — the endpoint is public per the Rosetta specification.
- **No privileges needed** — any external IP can send POST requests to `/network/status`.
- **Trivially repeatable** — a single attacker with modest bandwidth can sustain thousands of concurrent requests using standard HTTP tooling (`wrk`, `hey`, `ab`).
- **Default deployment is unprotected** — `global.middleware: false` means operators must explicitly opt in to protection; many deployments will not have done so.
- **Each request is expensive** — the `latestNodeServiceEndpoints` query in `address_book_entry.go` (lines 18–30) is a multi-table join with aggregation, executed up to twice per request, amplifying DB load per HTTP request.

### Recommendation
1. **Enable the middleware by default**: Change `global.middleware: false` to `global.middleware: true` in `charts/hedera-mirror-rosetta/values.yaml` line 95, so the `inFlightReq` and `rateLimit` Traefik rules are active out of the box.
2. **Add application-level concurrency control**: Insert a semaphore or token-bucket limiter in the Go middleware chain in `rosetta/main.go` before the router, so protection is not solely dependent on the ingress layer.
3. **Set an explicit `MaxOpenConnections`**: Ensure `Pool.MaxOpenConnections` has a safe non-zero default in the application configuration to bound DB connection usage regardless of ingress configuration.
4. **Cache `NetworkStatus` responses**: The genesis block and address book entries are nearly static; a short TTL cache (e.g., 5–10 seconds) would collapse thousands of concurrent requests into a single DB round-trip.

### Proof of Concept
```bash
# Prerequisites: rosetta running in online mode, default Helm deployment
# (global.middleware: false, no application-level rate limiting)

# Step 1: Confirm endpoint is reachable
curl -s -X POST http://<rosetta-host>/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' | jq .

# Step 2: Flood with concurrent requests to exhaust DB connections
hey -n 100000 -c 500 -m POST \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  http://<rosetta-host>/network/status

# Step 3: While flood is running, observe legitimate client failure
curl -s -X POST http://<rosetta-host>/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' | jq .
# Expected: {"code":500,"message":"There was an error connecting to the database...","retriable":false}

# Step 4: Confirm Rosetta client pre-submission check fails
rosetta-cli check:construction --configuration-file rosetta.json
# Expected: FAIL — network status check returns error, construction workflow aborted
```