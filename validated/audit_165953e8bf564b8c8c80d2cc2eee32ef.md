All referenced code was verified against the actual repository. Here is the audit result:

---

Audit Report

## Title
Unauthenticated `/network/status` Flood Triggers Retriable `ErrDatabaseError`, Enabling Amplified DoS via Client Retry Loop

## Summary
The `/network/status` endpoint in the Rosetta service is publicly accessible with no application-level rate limiting. Under DB connection pool exhaustion, it returns `ErrDatabaseError` with `Retriable: true`, which Rosetta-spec-compliant clients are required to retry. In default deployments the Traefik middleware chain (which includes a circuit breaker, in-flight limiter, and rate limiter) is entirely absent, leaving no automated mechanism to interrupt the resulting feedback loop.

## Finding Description

**`NetworkStatus()` code path — verified:**

`NetworkStatus()` in `rosetta/app/services/network_service.go` calls `n.addressBookEntryRepo.Entries(ctx)` at line 77. [1](#0-0) 

`Entries()` in `rosetta/app/persistence/address_book_entry.go` iterates over two address-book file IDs and executes a raw SQL query for each. On any `db.Raw(...).Scan(...)` error it returns `errors.ErrDatabaseError` at line 69. [2](#0-1) 

**`ErrDatabaseError` is `Retriable: true` — verified:**

`ErrDatabaseError` is declared at line 84 of `rosetta/app/errors/errors.go` as `newError(DatabaseError, 125, true)`. The `newError` helper at line 118 maps the third argument directly to `Retriable: retriable` in the `types.Error` struct. [3](#0-2) [4](#0-3) 

**No application-level rate limiting — verified:**

`rosetta/main.go` lines 217–219 assemble the middleware chain as `MetricsMiddleware → TracingMiddleware → CorsMiddleware`. There is no in-process rate limiter, concurrency cap, or circuit breaker. [5](#0-4) 

**Traefik middleware disabled by default — verified:**

`charts/hedera-mirror-rosetta/templates/middleware.yaml` gates the entire Traefik middleware chain on `{{ if and .Values.global.middleware .Values.middleware }}`. [6](#0-5) 

`charts/hedera-mirror-rosetta/values.yaml` sets `global.middleware: false` as the default. [7](#0-6) 

**Traefik retry amplification when middleware IS enabled — verified:**

When the middleware chain is enabled, it includes `retry: attempts: 3`, meaning Traefik internally retries each failed request three additional times (4× total backend hits per attacker request). [8](#0-7) 

The chain also includes a `circuitBreaker` (trips at >25% error ratio) and `inFlightReq: amount: 5` per IP, which would mitigate the attack — but only when `global.middleware` is `true`, which it is not by default. [9](#0-8) 

## Impact Explanation

DB connection pool exhaustion degrades every endpoint sharing the same `dbClient`. `RetrieveGenesis` and `RetrieveLatest` (called before `Entries` in `NetworkStatus`) also return `ErrDatabaseError` under pool exhaustion, making the entire online Rosetta node unavailable. Rosetta clients that depend on `/network/status` to determine the current block tip cannot construct or validate transactions, halting Rosetta-mediated transaction submission for the duration of the attack. [10](#0-9) 

## Likelihood Explanation

The endpoint requires no authentication, API key, or session. The attack requires only the ability to send HTTP POST requests. In default deployments (`global.middleware: false`) there is no circuit breaker, in-flight limiter, or rate limiter at any layer. The `Retriable: true` flag means every Rosetta-spec-compliant client (exchanges, validators, Rosetta CLI) that receives a DB error will immediately re-issue the same request, sustaining pool pressure without the attacker needing to maintain the original flood rate. [11](#0-10) 

## Recommendation

1. **Enable the Traefik middleware chain by default** — change `global.middleware` default to `true` in `charts/hedera-mirror-rosetta/values.yaml`. The existing `circuitBreaker`, `inFlightReq`, and `rateLimit` entries already provide the necessary protection; they are simply not activated. [11](#0-10) 

2. **Add in-process concurrency limiting** — add a semaphore or `golang.org/x/time/rate` limiter in the `NetworkStatus` handler or as a dedicated middleware in `rosetta/main.go`, so protection is present regardless of the Traefik deployment configuration. [5](#0-4) 

3. **Reconsider `Retriable: true` on `ErrDatabaseError` for `/network/status`** — or document that operators must ensure a circuit breaker is in place before exposing the endpoint publicly, since the retriable flag creates a client-driven amplification loop under DB stress. [3](#0-2) 

4. **Remove the `retry` middleware entry** (or move it to opt-in) — when the Traefik chain is enabled, `retry: attempts: 3` multiplies every failed request 4× at the backend, worsening the very DB pressure it is meant to survive. [8](#0-7) 

## Proof of Concept

```bash
# Flood /network/status with concurrent unauthenticated requests
for i in $(seq 1 500); do
  curl -s -X POST http://<rosetta-host>/network/status \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
done
wait

# Expected response once DB pool is exhausted:
# {"code":125,"message":"Database error","retriable":true,"details":null}
#
# A Rosetta-spec-compliant client receiving retriable:true will immediately
# re-issue the request, sustaining pool pressure without further attacker input.
```

### Citations

**File:** rosetta/app/services/network_service.go (L59-80)
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
```

**File:** rosetta/app/persistence/address_book_entry.go (L63-69)
```go
	for _, fileId := range []int64{aber.addressBook101.EncodedId, aber.addressBook102.EncodedId} {
		if err := db.Raw(
			latestNodeServiceEndpoints,
			sql.Named("file_id", fileId),
		).Scan(&nodes).Error; err != nil {
			log.Error("Failed to get latest node service endpoints", err)
			return nil, errors.ErrDatabaseError
```

**File:** rosetta/app/errors/errors.go (L84-84)
```go
	ErrDatabaseError                     = newError(DatabaseError, 125, true)
```

**File:** rosetta/app/errors/errors.go (L114-123)
```go
func newError(message string, statusCode int32, retriable bool) *types.Error {
	err := &types.Error{
		Message:   message,
		Code:      statusCode,
		Retriable: retriable,
		Details:   nil,
	}
	Errors = append(Errors, err)

	return err
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L88-95)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
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
