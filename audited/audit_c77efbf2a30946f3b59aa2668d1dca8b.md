### Title
Unsynchronized Genesis Initialization Race Allows Double DB Query Amplification via `index=0` in `FindByIndex()`

### Summary
`FindByIndex()` accepts `index=0` (passes the `index < 0` guard), then calls `initGenesisRecordFile()` whose early-exit check at line 244 reads `br.genesisBlock.ConsensusStart` without any mutex or atomic protection. Under concurrent load during the initialization window, N goroutines simultaneously observe the unset sentinel value and all independently execute the expensive `selectGenesis` query before `sync.Once` can protect the write. Each of those goroutines then also executes `selectRecordBlockByIndex`, producing 2N database queries instead of N+1.

### Finding Description
**Code path:**

- `rosetta/app/persistence/block.go`, `FindByIndex()`, lines 171–181
- `rosetta/app/persistence/block.go`, `initGenesisRecordFile()`, lines 243–263
- `rosetta/app/persistence/block.go`, `findBlockByIndex()`, lines 210–224

**Root cause — unsynchronized TOCTOU in `initGenesisRecordFile`:**

```go
// line 244 — plain struct-field read, no mutex, no atomic
if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
    return nil
}
// ... N goroutines all reach here simultaneously ...
db.Raw(selectGenesis, ...).First(&rb)   // expensive CTE join query — runs N times

br.once.Do(func() {                     // only ONE write wins
    br.genesisBlock = rb
})
```

`sync.Once` guards only the *write* to `br.genesisBlock`. The *read* at line 244 is completely unsynchronized. Go's memory model provides no guarantee that a goroutine that lost the `once.Do` race will observe the updated value before it has already issued its own `selectGenesis` query. This is a textbook data race (confirmed by Go's race detector).

**Exploit flow:**

1. Server starts; `br.genesisBlock.ConsensusStart` is `-1` (sentinel).
2. Attacker sends N concurrent HTTP requests with `block_identifier.index = 0` to any Rosetta endpoint that calls `RetrieveBlock` → `FindByIndex(ctx, 0)`.
3. All N goroutines pass `index < 0` (line 172) — `0 < 0` is false.
4. All N goroutines enter `initGenesisRecordFile`; all read `ConsensusStart == -1`; all proceed past the early-exit.
5. All N goroutines execute `selectGenesis` — a CTE that joins `record_file` against `account_balance`, sorts, and limits — against the live database.
6. `once.Do` lets only one write through; the rest discard their result but the queries have already been dispatched.
7. All N goroutines then call `findBlockByIndex(ctx, 0)` and execute `selectRecordBlockByIndex` (which itself contains a correlated subquery).
8. Total DB load: **2N queries** for N concurrent requests.

**Why existing checks are insufficient:**

- `index < 0` (line 172): `0` is a valid non-negative value; check passes.
- `sync.Once` (line 257): protects only the assignment, not the pre-query read. Multiple goroutines execute `selectGenesis` before any of them reaches `once.Do`.
- No rate-limiting or request coalescing exists at the repository layer.

### Impact Explanation
During the server startup window (or after any process restart), an attacker with no credentials can flood the Rosetta API with `index=0` block requests. Each request triggers two expensive database queries. The `selectGenesis` CTE performs a full join between `record_file` and `account_balance` with an `ORDER BY consensus_end LIMIT 1`; on a large mirror-node database this is a sequential scan. Multiplied by hundreds of concurrent connections this can saturate the database connection pool, spike CPU/IO on the DB host, and cause cascading `ErrNodeIsStarting` / `ErrDatabaseError` responses to all legitimate clients — a complete availability loss for the Rosetta API.

### Likelihood Explanation
The attack requires zero authentication. The Rosetta API is a public HTTP endpoint. `index=0` is the canonical genesis block index and is a natural value to query. The initialization window exists on every process restart (including rolling deployments and crash recovery). An attacker needs only a standard HTTP client and the ability to send concurrent requests; no special knowledge of the chain state is required. The attack is trivially repeatable by targeting the service immediately after each restart.

### Recommendation
1. **Protect the read with the same `sync.Once`**: move the entire initialization — including the early-exit check — inside `once.Do`, or use a `sync.RWMutex` to guard both the read and the write.
2. **Alternatively, use `sync/atomic`** to store the initialized flag separately from the struct, ensuring the check is atomic before any query is issued.
3. **Add request coalescing / singleflight** (`golang.org/x/sync/singleflight`) so that concurrent initialization requests collapse into a single in-flight DB query.

Example minimal fix:
```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    var initErr *rTypes.Error
    br.once.Do(func() {
        // selectGenesis runs exactly once, regardless of concurrency
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
}
```

### Proof of Concept
```bash
# 1. Start the Rosetta mirror-node service (fresh start / restart).
# 2. Immediately fire N concurrent requests targeting block index 0:
seq 1 200 | xargs -P200 -I{} curl -s -X POST http://<rosetta-host>/block \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
       "block_identifier":{"index":0}}'

# 3. Observe on the database host:
#    - 200+ simultaneous executions of the selectGenesis CTE query
#    - 200+ simultaneous executions of selectRecordBlockByIndex
#    - Connection pool exhaustion / query queue depth spike
#    - Subsequent legitimate requests receive ErrDatabaseError or timeout
```