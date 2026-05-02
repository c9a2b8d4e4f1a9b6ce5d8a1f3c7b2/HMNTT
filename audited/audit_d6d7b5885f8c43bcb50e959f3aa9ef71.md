### Title
Unauthenticated DB Connection Pool Exhaustion via Concurrent `/block` Hash-Only Requests

### Summary
The `Block()` handler in `rosetta/app/services/block_service.go` accepts hash-only `BlockIdentifier` requests from any unauthenticated caller and issues an unbounded number of simultaneous database queries through `FindByHash()`. The shared GORM connection pool is capped at `MaxOpenConnections=100` (default) with no application-level concurrency gate, and the Traefik rate-limiting middleware that could mitigate this is **disabled by default** (`global.middleware: false`). An attacker maintaining ≥100 concurrent requests can exhaust the pool, causing all subsequent Rosetta API queries — including block and transaction lookups used by exchanges — to queue indefinitely until the 20-second statement timeout expires per slot.

### Finding Description

**Exact code path:**

1. `Block()` at `rosetta/app/services/block_service.go:51` calls `s.RetrieveBlock(ctx, request.BlockIdentifier)`.
2. `RetrieveBlock()` at `rosetta/app/services/base_service.go:84-86` branches to `blockRepo.FindByHash(ctx, h)` when only `bIdentifier.Hash` is set (index is nil).
3. `FindByHash()` at `rosetta/app/persistence/block.go:135-144` calls `findBlockByHash()`.
4. `findBlockByHash()` at `rosetta/app/persistence/block.go:226-241` calls `br.dbClient.GetDbWithContext(ctx)` and executes `selectByHashWithIndex` — a correlated subquery against `record_file`.
5. `GetDbWithContext()` at `rosetta/app/db/client.go:22-37` wraps the caller's context with a **20-second timeout** (`time.Duration(d.statementTimeout)*time.Second`), meaning each connection is held for up to 20 seconds.
6. The pool is configured at `rosetta/app/db/db.go:33` via `sqlDb.SetMaxOpenConns(dbConfig.Pool.MaxOpenConnections)` — default **100** per `docs/configuration.md:660`.

**Root cause — failed assumption:**

The design assumes an external infrastructure layer (Traefik) will throttle concurrent requests before they reach the application. However, `charts/hedera-mirror-rosetta/values.yaml:95` sets `global.middleware: false`, and the middleware template at `charts/hedera-mirror-rosetta/templates/middleware.yaml:3` gates on `{{ if and .Values.global.middleware .Values.middleware }}` — so the `inFlightReq: amount: 5` and `rateLimit: average: 10` controls are **never instantiated** in a default deployment. The Go HTTP server itself imposes no concurrency limit; every incoming request spawns a goroutine that competes for a pool connection.

**Why existing checks fail:**

- The empty-hash guard at `block.go:136-138` only rejects a literal empty string; any non-empty (including random/fabricated) hash passes through to the DB.
- The `statementTimeout` context (20 s) bounds how long a single query runs but does not prevent 100 goroutines from simultaneously holding 100 connections for up to 20 s each.
- The `sync.Once` genesis initialization is a one-time cost and does not throttle subsequent `findBlockByHash` calls.
- The `maxTransactionsInBlock` guard at `block_service.go:61` is never reached when `FindByHash` itself is the bottleneck.

### Impact Explanation

All Rosetta API repository calls — block lookups, transaction lookups (`FindBetween`), account alias resolution — share the single GORM `DbClient` and therefore the same 100-connection pool. Once the pool is saturated, Go's `database/sql` queues new acquisition requests. Exchanges and integrators relying on `/block`, `/block/transaction`, and `/account/balance` receive either indefinitely delayed responses or context-cancelled errors. Because the Rosetta API is the primary interface for exchanges to confirm Hiero transactions, sustained pool exhaustion renders transaction confirmation unavailable for the duration of the attack.

### Likelihood Explanation

No authentication, API key, or session token is required. The `/block` endpoint is publicly reachable (ingress paths include `/rosetta/block` per `values.yaml:127`). Maintaining 100 concurrent long-running HTTP requests requires only a single machine with a modest HTTP load tool (e.g., `wrk`, `hey`, `ab`). Because each request with a non-existent hash still acquires a connection and executes a correlated subquery before returning `ErrBlockNotFound`, the attacker does not need valid block hashes. The attack is trivially repeatable and requires no special knowledge of the chain state.

### Recommendation

1. **Enable the Traefik middleware by default**: Change `global.middleware: false` to `global.middleware: true` in `charts/hedera-mirror-rosetta/values.yaml:95` so that `inFlightReq` and `rateLimit` are active out of the box.
2. **Add application-level concurrency control**: Introduce a semaphore (e.g., `golang.org/x/sync/semaphore`) in `Block()` or at the HTTP handler layer to cap simultaneous in-flight DB-bound requests independently of infrastructure.
3. **Reduce `statementTimeout`**: Lower the default from 20 s to a value consistent with expected query latency (e.g., 3–5 s) to release connections faster under load.
4. **Add a DB wait timeout**: Configure `db.SetConnMaxIdleTime` and a pool wait deadline so that goroutines waiting for a connection fail fast rather than queuing indefinitely.

### Proof of Concept

```bash
# Requires: wrk or hey; no credentials needed
# Target: default Rosetta deployment with global.middleware=false

# Generate 200 concurrent requests, each with a unique random hash
hey -n 100000 -c 200 -m POST \
  -H "Content-Type: application/json" \
  -d '{
    "network_identifier": {"blockchain":"Hiero","network":"mainnet"},
    "block_identifier": {"hash":"'$(cat /dev/urandom | head -c 32 | xxd -p)'"}
  }' \
  http://<rosetta-host>:5700/block

# While the above runs, observe legitimate requests timing out:
curl -s -m 5 -X POST http://<rosetta-host>:5700/block \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hiero","network":"mainnet"},"block_identifier":{}}'
# Expected: connection wait timeout / no response within 5 s
# Confirms: pool exhausted, legitimate queries queued indefinitely
```