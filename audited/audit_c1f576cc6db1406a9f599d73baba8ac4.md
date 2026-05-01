### Title
Misplaced `sync.Once` in `initGenesisRecordFile` Allows Concurrent `selectGenesis` DB Query Flood During Startup

### Summary
In `rosetta/app/persistence/block.go`, the `initGenesisRecordFile()` function uses `sync.Once` only to protect the *assignment* of `br.genesisBlock`, not the expensive `selectGenesis` database query that precedes it. The fast-path guard at line 244 is an unsynchronized read with no happens-before relationship to the write inside `once.Do`. Any number of concurrent goroutines can pass the guard simultaneously and each independently execute the `selectGenesis` CTE query against the database before `once.Do` completes, exhausting the DB connection pool during the startup window.

### Finding Description
**Exact code path:** `rosetta/app/persistence/block.go`, function `initGenesisRecordFile()`, lines 243–263.

```
243: func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
244:     if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {  // ← unsynchronized read
245:         return nil
246:     }
247:
248:     db, cancel := br.dbClient.GetDbWithContext(ctx)   // ← N goroutines reach here
249:     defer cancel()
250:
251:     var rb recordBlock
252:     if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {  // ← N queries fire
253:         ...
254:     }
255:
257:     br.once.Do(func() {          // ← only protects the write, not the query above
258:         br.genesisBlock = rb
259:     })
```

**Root cause / failed assumption:** The developer assumed `sync.Once` would prevent duplicate work. It does not — `once.Do` only serializes the *closure* (the assignment). The expensive DB query at lines 252–254 is entirely outside the `once.Do` scope. The guard read at line 244 is also unsynchronized: Go's memory model provides no happens-before guarantee between the write inside `once.Do` (line 258) and the read at line 244 in a different goroutine, making this a formal data race.

**Exploit flow:**
1. Attacker sends a burst of N concurrent HTTP requests to any Rosetta endpoint (`/block`, `/block/transaction`, `/network/status`, etc.) immediately after (or during) service startup, before the first `selectGenesis` query completes.
2. All N goroutines enter `initGenesisRecordFile` simultaneously.
3. All N goroutines read `br.genesisBlock.ConsensusStart == -1` at line 244 (genesis not yet set).
4. All N goroutines proceed past the guard and each calls `GetDbWithContext`, acquiring N connections from the pool.
5. All N goroutines execute the `selectGenesis` CTE query (a JOIN across `account_balance` and `record_file` with ORDER BY) concurrently.
6. `once.Do` fires for the first goroutine to arrive; the remaining N-1 goroutines' closures are silently dropped — but their DB queries have already been dispatched.

**Why existing checks fail:** `sync.Once` is the only concurrency control present. It is placed *after* the DB query, so it cannot prevent duplicate queries. There is no mutex, atomic, or channel guarding the query execution path.

### Impact Explanation
The Rosetta DB pool is configured with `maxOpenConnections: 100` by default (documented in `docs/configuration.md` line 660 and set in `rosetta/app/db/db.go` line 33). A burst of 100 concurrent requests during the startup window saturates the entire connection pool with `selectGenesis` queries. While each query is bounded (`LIMIT 1`), the CTE involves a JOIN between `account_balance` and `record_file` with an `ORDER BY consensus_end` — on a large mirror-node database this is non-trivial. With all 100 connections occupied, every other concurrent request (including legitimate ones) blocks waiting for a free connection, causing request timeouts and effective service unavailability for the duration of the query burst. The Rosetta API is a critical infrastructure component used by exchanges and custodians to construct and verify Hedera transactions.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no privileged access — only the ability to send HTTP requests to the public Rosetta port (default 5700). The startup window is the only requirement; an attacker can either monitor for service restarts (e.g., via deployment notifications, health-check polling, or simply sending requests continuously) and fire the burst at the right moment. The attack is trivially scriptable with any HTTP load tool (`wrk`, `hey`, `ab`). Because the Rosetta API is intended to be publicly reachable by exchange infrastructure, rate limiting is typically absent or permissive.

### Recommendation
Move the entire initialization — including the DB query — inside `once.Do`:

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    var initErr *rTypes.Error
    br.once.Do(func() {
        db, cancel := br.dbClient.GetDbWithContext(ctx)
        defer cancel()
        var rb recordBlock
        if err := db.Raw(selectGenesis, sql.Named("treasury_entity_id",
            br.treasuryEntityId.EncodedId)).First(&rb).Error; err != nil {
            initErr = handleDatabaseError(err, hErrors.ErrNodeIsStarting)
            return
        }
        br.genesisBlock = rb
        log.Infof("Fetched genesis record file, index - %d", rb.Index)
    })
    // If once.Do already ran successfully, genesisBlock is set; check it.
    if initErr == nil && br.genesisBlock.ConsensusStart == genesisConsensusStartUnset {
        return hErrors.ErrNodeIsStarting
    }
    return initErr
}
```

This guarantees exactly one DB query regardless of concurrency, eliminates the data race on `br.genesisBlock.ConsensusStart`, and preserves the fast-path behavior for all subsequent calls (since `once.Do` is a no-op after the first execution).

### Proof of Concept
```bash
# 1. Start the Rosetta service (or wait for a restart)
# 2. Immediately fire 100 concurrent requests to the /network/status endpoint
#    (which calls RetrieveGenesis -> initGenesisRecordFile)

hey -n 500 -c 100 -m POST \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  http://<rosetta-host>:5700/network/status

# Expected result during startup window:
# - All 100 concurrent goroutines pass the line-244 guard simultaneously
# - 100 selectGenesis queries execute concurrently, saturating the DB pool
# - Subsequent requests time out waiting for a free connection
# - DB server shows 100 identical CTE queries running in parallel
# - Service logs show N "Fetched genesis record file" messages (one per goroutine
#   that reached once.Do), confirming multiple queries fired
```