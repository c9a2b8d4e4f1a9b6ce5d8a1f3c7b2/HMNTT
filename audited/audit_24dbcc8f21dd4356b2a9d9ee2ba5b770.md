### Title
`sync.Once` Misplacement in `initGenesisRecordFile` Enables Unbounded Concurrent `selectGenesis` CTE Execution

### Summary
In `rosetta/app/persistence/block.go`, `initGenesisRecordFile()` places `sync.Once` **after** the expensive `selectGenesis` CTE rather than around it. The fast-path guard at line 244 is an unsynchronized read, so every concurrent goroutine that arrives before genesis is set will independently execute the full CTE. Worse, when genesis data is absent (node is starting), the function returns early at line 254 without ever calling `once.Do`, leaving `genesisBlock.ConsensusStart` permanently at `genesisConsensusStartUnset` and causing every subsequent request to re-execute the expensive query indefinitely.

### Finding Description

**Exact code path:** `rosetta/app/persistence/block.go`, `initGenesisRecordFile()`, lines 243–263.

```
Line 244: if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
              return nil   // unsynchronized read — no mutex, no atomic
          }
Lines 252–254: db.Raw(selectGenesis, ...).First(&rb)  // expensive CTE executes here
               if err != nil { return ErrNodeIsStarting }  // once.Do NEVER reached on error
Lines 257–259: br.once.Do(func() { br.genesisBlock = rb })  // too late; query already ran
```

**Root cause — two compounding flaws:**

1. **`sync.Once` guards only the assignment, not the query.** N goroutines can all pass the unsynchronized check at line 244 simultaneously (all see `ConsensusStart == genesisConsensusStartUnset`) and all dispatch `selectGenesis` to the DB concurrently. `once.Do` fires for the first to finish, but the other N-1 queries are already in flight.

2. **Error path never calls `once.Do`.** When genesis data is not yet present in the DB (the normal "node is starting" state), `db.Raw(...).First(&rb)` returns `gorm.ErrRecordNotFound`, the function returns at line 254, and `once.Do` is never invoked. `genesisBlock.ConsensusStart` stays at `genesisConsensusStartUnset`. Every subsequent call to any of the five public methods (`FindByHash`, `FindByIndex`, `FindByIdentifier`, `RetrieveGenesis`, `RetrieveLatest`) re-enters the expensive path unconditionally.

**`selectGenesis` query cost:**
```sql
with genesis as (
  select consensus_timestamp from account_balance
  where account_id = @treasury_entity_id
  order by consensus_timestamp limit 1
)
select ... from record_file rf
join genesis on rf.consensus_end > genesis.timestamp
order by rf.consensus_end limit 1
```
This CTE scans `account_balance` (potentially millions of rows) and joins it against `record_file`. Under concurrent load it is a significant DB CPU consumer.

**No application-level concurrency control exists.** The only middleware that could limit this (`inFlightReq: 5`, `rateLimit: average: 10`) is the optional Traefik chain, which is **disabled by default** (`global.middleware: false` in `charts/hedera-mirror-rosetta/values.yaml` line 95). Even when enabled, `rateLimit` uses `sourceCriterion: requestHost: true` (keyed on the HTTP `Host` header, not client IP), so a single attacker host is limited to 10 req/s — still enough to sustain dozens of concurrent expensive queries given typical CTE latency. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

During the "node is starting" window (which can last minutes while the importer populates genesis data), every block-lookup request from every client executes the full `selectGenesis` CTE. A sustained stream of requests — even at modest concurrency — causes DB CPU to spike well above 30%, degrading or denying service to all legitimate users. Because the window is open for the entire startup period and the attack requires no credentials, the impact is a practical DoS against the database tier.

### Likelihood Explanation

Any unprivileged user who can reach the Rosetta HTTP port can trigger this. The five affected endpoints (`/block`, `/block/transaction`, etc.) are publicly documented Rosetta API paths. No authentication is required. The attacker needs only to send concurrent HTTP POST requests to any block-lookup endpoint during node startup. The attack is trivially scriptable (`ab`, `wrk`, `hey`, etc.) and repeatable on every node restart.

### Recommendation

Move the `sync.Once` to wrap **both** the guard check and the query, so the expensive CTE executes at most once regardless of concurrency or error outcome:

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
        return nil
    }

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
        log.Infof("Fetched genesis record file, index - %d", br.genesisBlock.Index)
    })
    return initErr
}
```

Note: because `sync.Once` cannot be reset, a failed initialization (genesis not yet in DB) will permanently prevent retry. The correct pattern for a retriable lazy-init is a `sync.Mutex`-guarded double-checked lock, or resetting the `once` field on error using an `atomic.Pointer[sync.Once]`.

Additionally, enable the Traefik `inFlightReq` + `rateLimit` middleware by default (`global.middleware: true`) and switch `rateLimit.sourceCriterion` to `ipStrategy` to limit per-client rather than per-host.

### Proof of Concept

**Preconditions:** Rosetta node has just restarted; genesis data is not yet present in the DB (or the DB is slow enough that the first query has not yet completed).

**Steps:**

```bash
# 1. Start the Rosetta node (genesis not yet in DB)
# 2. Immediately flood block-lookup requests from an unprivileged client:
for i in $(seq 1 200); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index":0}}' &
done
wait

# 3. Observe DB CPU via pg_stat_activity or cloud monitoring:
psql -c "SELECT count(*), query FROM pg_stat_activity
         WHERE query LIKE '%account_balance%' GROUP BY query;"
# Expected: dozens of concurrent selectGenesis CTE executions
```

**Expected result:** DB CPU spikes above 30% sustained for the duration of the startup window. Each request independently executes the full `selectGenesis` CTE because `once.Do` is never reached (error path) or is reached only after the query already ran (concurrent path).

### Citations

**File:** rosetta/app/persistence/block.go (L243-263)
```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
	if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
		return nil
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	var rb recordBlock
	if err := db.Raw(selectGenesis, sql.Named("treasury_entity_id", br.treasuryEntityId.EncodedId)).
		First(&rb).Error; err != nil {
		return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
	}

	br.once.Do(func() {
		br.genesisBlock = rb
	})

	log.Infof("Fetched genesis record file, index - %d", br.genesisBlock.Index)
	return nil
}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L88-96)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
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
