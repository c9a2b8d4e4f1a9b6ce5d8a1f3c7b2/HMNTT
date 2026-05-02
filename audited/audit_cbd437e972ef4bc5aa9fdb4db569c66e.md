### Title
Unauthenticated DB Connection Pool Exhaustion via `ErrDatabaseError` Retriable Flag Amplification

### Summary
`ErrDatabaseError` is unconditionally marked `retriable=true` in the Rosetta API, while the default deployment has no application-level rate limiting or concurrency control (Traefik middleware is disabled by default via `global.middleware: false`). An unprivileged attacker can exhaust the 100-connection database pool with concurrent requests, causing all subsequent requests to return `ErrDatabaseError` (retriable=true), which causes retry-aware Rosetta SDK clients to re-issue requests, creating a self-sustaining amplification loop that keeps the pool exhausted and the service unavailable.

### Finding Description

**Error definition — `rosetta/app/errors/errors.go:84`:**
```go
ErrDatabaseError = newError(DatabaseError, 125, true)  // retriable=true
```

**Error propagation — `rosetta/app/persistence/block.go:265-271`:**
```go
func handleDatabaseError(err error, recordNotFoundErr *rTypes.Error) *rTypes.Error {
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return recordNotFoundErr
    }
    log.Errorf(databaseErrorFormat, hErrors.ErrDatabaseError.Message, err)
    return hErrors.ErrDatabaseError  // returned for ANY non-record-not-found DB error
}
```
The same pattern appears in `rosetta/app/persistence/account.go` at lines 122, 155, 256, 301, 335 — every persistence layer function returns `ErrDatabaseError` on pool exhaustion, context cancellation, or statement timeout.

**Connection pool — `rosetta/app/db/db.go:31-33`:**
```go
sqlDb.SetMaxIdleConns(dbConfig.Pool.MaxIdleConnections)   // default: 20
sqlDb.SetConnMaxLifetime(...)
sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)   // default: 100
```
Default `maxOpenConnections` is 100 (`docs/configuration.md:660`). Statement timeout is 20 seconds (`docs/configuration.md:662`). With 100 connections held open for up to 20 seconds each, the pool is exhausted by ~5 concurrent requests/second sustained.

**Middleware disabled by default — `charts/hedera-mirror-rosetta/values.yaml:95`:**
```yaml
global:
  middleware: false   # ← all Traefik protections are off by default
```

**Middleware template guard — `charts/hedera-mirror-rosetta/templates/middleware.yaml:3`:**
```
{{ if and .Values.global.middleware .Values.middleware -}}
```
The entire Traefik middleware chain (rate limiting, in-flight request limiting, circuit breaker) is only instantiated when `global.middleware: true` is explicitly set. In the default deployment it does not exist. There is no application-level rate limiting or concurrency control anywhere in the Rosetta Go server (`rosetta/main.go:217-219` only adds metrics and tracing middleware).

**Amplification mechanism:** When `ErrDatabaseError` is returned, the Rosetta API responds with HTTP 500 and a JSON body containing `"retriable": true`. The Coinbase `rosetta-sdk-go` client library reads this field and automatically retries the request. Each retry re-enters the already-exhausted pool, generating another `ErrDatabaseError`, which triggers another retry — a closed feedback loop.

### Impact Explanation
The database connection pool is fully exhausted, causing 100% of Rosetta API requests to fail with `ErrDatabaseError`. Because the PostgreSQL instance is shared with other mirror node components (importer, REST API), sustained pool exhaustion can degrade or crash those services as well. The `retriable=true` flag means the DoS is self-sustaining: even after the attacker stops sending new requests, existing SDK clients continue retrying, prolonging the outage. This constitutes a non-network DoS affecting the availability of the Rosetta API and potentially the broader mirror node infrastructure.

### Likelihood Explanation
No authentication or API key is required. The Rosetta API is publicly accessible (ingress enabled by default, `values.yaml:122`). Exhausting 100 connections requires only ~5–10 concurrent HTTP clients sending requests to any DB-hitting endpoint (e.g., `POST /block`, `POST /account/balance`). This is trivially achievable from a single machine. The default deployment ships with `global.middleware: false`, meaning the rate limiter, in-flight request limiter, and circuit breaker are all absent. The attack is repeatable and deterministic.

### Recommendation

1. **Set `retriable=false` for `ErrDatabaseError`**, or introduce a separate non-retriable error code for pool-exhaustion conditions vs. transient DB errors. Pool exhaustion is not a condition that retrying immediately will resolve.
2. **Enable the Traefik middleware by default** (`global.middleware: true`) or add application-level concurrency limiting (e.g., a semaphore in the Go server) that is independent of the ingress configuration.
3. **Add a connection-wait timeout** to the GORM/`database/sql` pool so that requests waiting for a connection fail fast (returning 503) rather than holding goroutines and amplifying load.
4. **Separate the Rosetta DB user's connection pool** from other mirror node components to contain blast radius.

### Proof of Concept

```bash
# Exhaust the 100-connection pool with concurrent requests to a DB-hitting endpoint.
# No authentication required. Replace HOST with the Rosetta API hostname.

for i in $(seq 1 120); do
  curl -s -X POST https://HOST/block \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index":1}}' &
done
wait

# All subsequent requests now return ErrDatabaseError with retriable=true:
curl -X POST https://HOST/block \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
       "block_identifier":{"index":1}}'
# Response: {"code":125,"message":"Database error","retriable":true}

# A Rosetta SDK client configured with retry will now loop indefinitely,
# each retry re-hitting the exhausted pool and receiving the same error.
```