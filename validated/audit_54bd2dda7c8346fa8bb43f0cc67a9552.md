I verified all technical claims against the actual code. Here is my assessment:

---

Audit Report

## Title
Unauthenticated DoS via DB Connection Exhaustion on `/network/status` with Rate-Limiting Disabled by Default

## Summary
`NetworkStatus()` in `rosetta/app/services/network_service.go` executes multiple sequential database queries per request. The Traefik middleware chain providing `inFlightReq` and `rateLimit` protection is gated behind `global.middleware: false` in the default Helm values, meaning it is off by default. An unprivileged attacker can flood the endpoint with concurrent requests, exhaust the finite DB connection pool, and deny service to all legitimate clients.

## Finding Description

**Code path — per-request DB load (verified):**

`NetworkStatus()` makes three sequential repository calls: [1](#0-0) 

1. `n.RetrieveGenesis(ctx)` (line 67)
2. `n.RetrieveLatest(ctx)` (line 72)
3. `n.addressBookEntryRepo.Entries(ctx)` (line 77)

The `AddressBookEntryRepository` is constructed with two address book file IDs (101 and 102), making up to two SQL queries per `Entries()` call: [2](#0-1) 

**DB connection pool — finite resource (verified):**

`ConnectToDb` calls `sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)`, establishing a hard ceiling on concurrent DB connections: [3](#0-2) 

When all slots are occupied, new queries block until a slot is freed or the context times out.

**No application-level rate limiting (verified):**

`main.go` assembles the middleware stack as `MetricsMiddleware → TracingMiddleware → CorsMiddleware → Router` with no rate limiter, semaphore, or in-flight request cap: [4](#0-3) 

**Traefik middleware disabled by default (verified):**

The Helm chart defines `inFlightReq` (5 concurrent per IP) and `rateLimit` (10 req/s) in `values.yaml`: [5](#0-4) 

But the middleware CRDs are only created when **both** `global.middleware` and `middleware` are truthy: [6](#0-5) 

The default value is `global.middleware: false`: [7](#0-6) 

With this default, no Traefik Middleware CRDs are deployed, so no rate limiting or concurrency limiting is active.

**Additional amplification when middleware IS enabled (verified):**

The `retry` middleware is configured with `attempts: 3`, meaning each attacker request can trigger up to 3 upstream DB-hitting requests: [8](#0-7) 

`inFlightReq` uses `ipStrategy: depth: 1` (reads `X-Forwarded-For[0]`), which an attacker can spoof to bypass the per-IP cap: [9](#0-8) 

`rateLimit` uses `sourceCriterion: requestHost: true` — a single global bucket shared by all clients, not per-source-IP: [10](#0-9) 

## Impact Explanation
An attacker who exhausts `MaxOpenConnections` causes all subsequent DB operations across the entire Rosetta service to block or fail. This affects not only `/network/status` but every other online-mode endpoint (`/block`, `/account/balance`, etc.) that shares the same GORM pool. The result is a complete service outage for all legitimate clients. No authentication is required; the endpoint is publicly reachable by design per the Rosetta API specification.

## Likelihood Explanation
The attack requires only an HTTP client capable of sending concurrent POST requests to `/network/status` — no credentials, no special knowledge, no exploit chain. The default Helm deployment ships with `global.middleware: false`, meaning deployments using the standalone `hedera-mirror-rosetta` chart have zero ingress-level protection out of the box. Even operators who set `global.middleware: true` face the `X-Forwarded-For` spoofing bypass for `inFlightReq` and the retry amplification. The attack is trivially scriptable with tools like `ab`, `wrk`, or `hey`.

## Recommendation

1. **Application-level concurrency control:** Add a semaphore or `golang.org/x/time/rate` rate limiter inside the Go application, independent of any infrastructure middleware, to cap concurrent in-flight requests to `/network/status`.
2. **Change the default:** Set `global.middleware: true` in `charts/hedera-mirror-rosetta/values.yaml` so the Traefik middleware chain is active by default.
3. **Fix `inFlightReq` IP strategy:** Replace `ipStrategy: depth: 1` with a strategy that cannot be spoofed via `X-Forwarded-For`, or use `ipStrategy: excludedIPs` to trust only known proxy ranges.
4. **Fix `rateLimit` source criterion:** Replace `requestHost: true` with `ipStrategy` so the rate limit is per-source-IP rather than a single global bucket.
5. **Remove or reduce `retry`:** The `attempts: 3` retry multiplier amplifies load 3x; reduce attempts or scope retries to network errors only, not application errors.
6. **Set a conservative `MaxOpenConnections` default** and document it explicitly so operators understand the pool ceiling.

## Proof of Concept

```bash
# Flood /network/status with 500 concurrent requests, 10000 total
hey -n 10000 -c 500 -m POST \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  http://<rosetta-host>/network/status
```

With `global.middleware: false` (the default), all 500 concurrent goroutines will each attempt to acquire DB connections. Once `MaxOpenConnections` slots are exhausted, all subsequent requests — including from legitimate clients — will block or time out, producing a complete service outage. When middleware IS enabled, prepend a spoofed `X-Forwarded-For` header (`-H "X-Forwarded-For: <rotating-IP>"`) to bypass the `inFlightReq` per-IP cap.

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

**File:** rosetta/main.go (L71-71)
```go
	addressBookEntryRepo := persistence.NewAddressBookEntryRepository(systemEntity.GetAddressBook101(), systemEntity.GetAddressBook102(), dbClient)
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

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```
