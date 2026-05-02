### Title
Repeated Unbounded `selectGenesis` Query Execution via Concurrent `/network/status` Requests During Genesis Initialization Failure

### Summary
`initGenesisRecordFile()` in `rosetta/app/persistence/block.go` uses `sync.Once` to cache the genesis block, but only invokes `once.Do` on a **successful** DB query. When the query fails (e.g., genesis data not yet ingested — the normal startup state), the sentinel value `genesisConsensusStartUnset` (-1) is never replaced, so every concurrent `NetworkStatus()` call passes the early-exit guard and re-executes the expensive `selectGenesis` CTE join. An unauthenticated attacker can flood `/network/status` during this window to saturate DB CPU and starve transaction confirmation queries.

### Finding Description

**Exact code path:**

`rosetta/app/services/network_service.go` → `NetworkStatus()` (line 67) calls `n.RetrieveGenesis(ctx)`, which delegates to `blockRepository.RetrieveGenesis()` (line 183–188 of `block.go`), which calls `initGenesisRecordFile()` (lines 243–263).

```go
// block.go lines 243-263
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {  // line 244
        return nil
    }
    // ... executes selectGenesis SQL ...
    if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)  // once.Do NOT reached
    }
    br.once.Do(func() {          // only called on success
        br.genesisBlock = rb
    })
    ...
}
```

**Root cause:** `br.once.Do` is only reached when `selectGenesis` succeeds. If the query returns `ErrRecordNotFound` (no genesis data yet), the function returns early at the error branch, `once.Do` is never called, and `br.genesisBlock.ConsensusStart` remains `-1`. Every subsequent goroutine that calls `initGenesisRecordFile` passes the guard at line 244 and re-executes `selectGenesis` against the DB.

**The `selectGenesis` query** (lines 49–72) is a multi-step CTE:
1. Scans `account_balance` filtered by `account_id`, ordered, limit 1.
2. Cross-joins `record_file` on `rf.consensus_end > genesis.timestamp`.
3. Executes a **correlated subquery** per candidate row in `record_file` (`select rf1.consensus_start-1 from record_file rf1 where rf1.index = rf.index + 1`).
4. Orders by `rf.consensus_end`, limit 1.

This is non-trivial under load, especially as `record_file` grows.

**Why the `sync.Once` check is insufficient:** `once.Do` is a correct one-shot mechanism, but it is only armed after a successful query. The guard at line 244 is an unsynchronized read of `br.genesisBlock.ConsensusStart` that is never set to a non-sentinel value until success. During the startup window (which can last minutes while the importer ingests the genesis balance file), every request passes the guard and hits the DB.

**No application-level rate limiting:** `main.go` (lines 217–227) applies only metrics/tracing/CORS middleware. The Traefik `inFlightReq`/`rateLimit` middleware in `charts/hedera-mirror-rosetta/values.yaml` (lines 152–161) is gated on `global.middleware: true` (line 95 shows `global.middleware: false` as default) and is infrastructure-optional — not enforced at the application layer.

### Impact Explanation

During the startup phase (which is a normal, expected, and potentially prolonged state), an attacker can issue a high volume of concurrent `POST /network/status` requests. Each request independently executes `selectGenesis` against the PostgreSQL database. With sufficient concurrency, DB CPU is saturated. Because the mirror node's importer and other internal components share the same database, transaction ingestion and confirmation queries are starved of DB resources, causing a network-wide transaction confirmation outage for the duration of the attack. The endpoint requires no authentication.

### Likelihood Explanation

The attack requires no credentials, no special knowledge beyond the public Rosetta API spec, and no exploit tooling beyond a standard HTTP load generator (e.g., `wrk`, `hey`, `ab`). The startup window is predictable (observable via the `ErrNodeIsStarting` response code returned to callers). An attacker can trivially detect this state and begin flooding. The attack is repeatable: any restart of the rosetta service resets `br.genesisBlock` to the sentinel value, reopening the window. Infrastructure-level rate limiting is not guaranteed to be deployed.

### Recommendation

1. **Move `once.Do` to wrap the entire initialization block**, not just the assignment, so that concurrent goroutines block on `once.Do` rather than all racing to execute the query:

```go
var initErr *rTypes.Error
br.once.Do(func() {
    db, cancel := br.dbClient.GetDbWithContext(ctx)
    defer cancel()
    var rb recordBlock
    if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {
        initErr = handleDatabaseError(err, hErrors.ErrNodeIsStarting)
        return
    }
    br.genesisBlock = rb
})
return initErr
```

   However, note that `sync.Once` does not retry on failure. A better pattern is to use a mutex-protected flag that is only set to "initialized" on success, allowing retries until success and then caching permanently.

2. **Use a `sync.RWMutex`** to protect both the read (guard check) and write (assignment), with a boolean `initialized` flag separate from the sentinel value.

3. **Enforce application-level concurrency limits** on the `/network/status` endpoint independent of infrastructure middleware.

### Proof of Concept

**Preconditions:** Rosetta node is starting up (importer has not yet ingested the genesis account balance file). The `/network/status` endpoint returns `{"code":..., "message":"Node is starting"}`.

**Steps:**

```bash
# Confirm node is in starting state
curl -s -X POST http://<rosetta-host>:5700/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"testnet"}}' \
  | grep "starting"

# Flood with concurrent requests (no auth required)
hey -n 10000 -c 200 -m POST \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"testnet"}}' \
  http://<rosetta-host>:5700/network/status
```

**Result:** Each of the 200 concurrent goroutines passes the `genesisConsensusStartUnset` guard at `block.go:244`, executes `selectGenesis` against the DB, fails, and returns `ErrNodeIsStarting` — without ever setting the cache. DB CPU spikes to saturation. Transaction confirmation queries issued by the importer are delayed or time out, halting block ingestion for the duration of the attack.