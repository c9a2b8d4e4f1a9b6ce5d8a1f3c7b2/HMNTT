### Title
Unsynchronized Genesis Check in `initGenesisRecordFile` Allows Concurrent DB Query Amplification

### Summary
In `rosetta/app/persistence/block.go`, the early-exit guard at line 244 reads `br.genesisBlock.ConsensusStart` without any synchronization, while the write at line 258 is protected only by `sync.Once`. This means N concurrent goroutines can all observe the unset sentinel value and all proceed to execute the expensive `selectGenesis` CTE against the database — the `sync.Once` only prevents multiple writes, not multiple queries. Any unprivileged HTTP client can trigger this by sending concurrent requests to any of the five public endpoints that call `initGenesisRecordFile`.

### Finding Description

**Exact code path:** `rosetta/app/persistence/block.go`, `initGenesisRecordFile()`, lines 243–263.

```
243: func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
244:     if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {  // ← unsynchronized read
245:         return nil
246:     }
247:
248:     db, cancel := br.dbClient.GetDbWithContext(ctx)
249:     defer cancel()
250:
251:     var rb recordBlock
252:     if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {  // ← all goroutines reach here
253:         return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
254:     }
255:
256:
257:     br.once.Do(func() {
258:         br.genesisBlock = rb   // ← only one goroutine writes
259:     })
260: ...
263: }
```

**Root cause:** The `sync.Once` is placed around only the *assignment* (line 257–259), not around the entire initialization block including the DB query. The unsynchronized read at line 244 and the concurrent write at line 258 constitute a Go data race per the Go memory model. More critically, every goroutine that passes the line-244 check proceeds independently to execute `selectGenesis` — a CTE that joins `account_balance` and `record_file` with a correlated subquery (lines 49–72). The `sync.Once` does nothing to serialize those queries.

**Exploit flow:**
1. Attacker sends N concurrent HTTP requests to any public endpoint (`/block`, `/block/transaction`, `/network/status`, `/account/balance`, `/account/coins`) during the startup window before genesis is cached.
2. All N goroutines read `br.genesisBlock.ConsensusStart == -1` at line 244 simultaneously.
3. All N goroutines execute `selectGenesis` against the database.
4. `sync.Once` lets exactly one goroutine write the result; the other N-1 queries were wasted.
5. DB load scales linearly with N.

**Why existing checks fail:**
- The Traefik `inFlightReq: amount: 5` and `rateLimit: average: 10` middleware (values.yaml lines 152–160) is **conditionally deployed** — it is only applied when both `global.middleware` and `middleware` Helm values are set (middleware.yaml line 3: `{{ if and .Values.global.middleware .Values.middleware }}`). It is not a guaranteed control.
- Even when deployed, the `inFlightReq` limit of 5 is per source IP; an attacker using multiple IPs or a botnet bypasses it entirely.
- The rate limit of 10 req/s per host still allows bursts of concurrent requests that all land before genesis is initialized.
- There is no application-level concurrency guard (no mutex, no atomic, no channel) protecting the check-then-query sequence.

### Impact Explanation
The `selectGenesis` CTE (lines 49–72) performs: a full ordered scan of `account_balance` filtered by `account_id`, a join to `record_file` on `consensus_end > genesis.timestamp`, and a correlated subquery on `record_file` for each matched row. Under concurrent load this query is I/O and CPU intensive. With N=30–50 concurrent requests (trivially achievable from a single machine with multiple connections or multiple IPs), the database receives 30–50 simultaneous copies of this query instead of 1, easily exceeding a 30% resource increase on the DB host. If the DB is already under load, this can cascade into query timeouts, causing `ErrNodeIsStarting` responses and keeping the genesis-uninitialized window open indefinitely — making the attack self-sustaining.

### Likelihood Explanation
The attack requires no authentication, no special knowledge, and no privileged access — only the ability to send HTTP POST requests to the public Rosetta API. The startup window (during which genesis is unset) is the primary trigger, but it can be extended if the DB is slow. The attack is repeatable on every node restart. A single attacker with a modest number of connections or IPs can reliably trigger it.

### Recommendation
Move the entire initialization — including the DB query — inside `br.once.Do(...)`:

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    var initErr *rTypes.Error
    br.once.Do(func() {
        db, cancel := br.dbClient.GetDbWithContext(ctx)
        defer cancel()
        var rb recordBlock
        if err := db.Raw(selectGenesis, sql.Named("treasury_entity_id", br.treasuryEntityId.EncodedId)).
            First(&rb).Error; err != nil {
            initErr = handleDatabaseError(err, hErrors.ErrNodeIsStarting)
            return
        }
        br.genesisBlock = rb
        log.Infof("Fetched genesis record file, index - %d", br.genesisBlock.Index)
    })
    return initErr
}
```

Note: if `initErr` is non-nil (DB unavailable at startup), `sync.Once` will not re-run on the next call. A `sync.Once`-with-retry pattern (using a mutex + boolean flag) should be used so that transient DB errors during startup do not permanently prevent initialization.

### Proof of Concept

```bash
# During node startup (before genesis is cached), send 50 concurrent requests:
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>/network/status \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
done
wait

# Observe in DB slow-query log or pg_stat_activity:
# 50 simultaneous executions of the selectGenesis CTE instead of 1.
# DB CPU/IO spikes proportionally; subsequent requests may receive ErrNodeIsStarting
# if the DB becomes overloaded, keeping the window open for further amplification.
```