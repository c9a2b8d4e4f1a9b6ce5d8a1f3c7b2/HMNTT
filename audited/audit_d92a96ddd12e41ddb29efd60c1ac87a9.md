### Title
Unbounded Concurrent `selectGenesis` DB Queries in `initGenesisRecordFile` Due to Misplaced `sync.Once`

### Summary
`blockRepository.initGenesisRecordFile` runs the expensive `selectGenesis` SQL query *outside* of `sync.Once`, so N concurrent callers all execute the query independently before any deduplication occurs. When the query fails (the normal "node is starting" condition), `once.Do` is never invoked, leaving `genesisBlock.ConsensusStart` permanently at `-1` and causing every subsequent request to re-execute `selectGenesis` with no bound, for the entire duration of the startup window.

### Finding Description
**Code location:** `rosetta/app/persistence/block.go`, `initGenesisRecordFile()`, lines 243–263, called unconditionally from `RetrieveLatest()` at line 191.

```
// line 243
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {   // (A) unsynchronized read
        return nil
    }
    // ... (B) selectGenesis query runs here, BEFORE once.Do ...
    if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)      // (C) once.Do never reached
    }
    br.once.Do(func() { br.genesisBlock = rb })                         // (D) only reached on success
}
```

**Root cause — two independent flaws:**

1. **Query outside `sync.Once`:** The guard at (A) is an unsynchronized field read. N goroutines arriving simultaneously all see `ConsensusStart == -1` and all proceed to execute `selectGenesis` at (B). `sync.Once` at (D) only serializes the *assignment*, not the query, so N queries are issued.

2. **`once.Do` never fires on failure:** During node startup the genesis row is absent, so (B) returns an error and execution returns at (C). `once.Do` is never called, `genesisBlock.ConsensusStart` stays `-1`, and the check at (A) never short-circuits. Every subsequent request re-runs `selectGenesis` indefinitely.

**Exploit flow:**
- Attacker sends a steady stream of `POST /block` (or any endpoint routing through `RetrieveLatest`) during the startup window.
- Each request independently executes `selectGenesis` (CTE joining `account_balance` + `record_file` with a correlated subquery and `ORDER BY consensus_end LIMIT 1`) and, if genesis succeeds, also `selectLatestWithIndex` (`ORDER BY index DESC LIMIT 1`).
- No in-process deduplication or queuing exists; the Traefik `inFlightReq: 5` limit is per-IP and is trivially bypassed with multiple source addresses.

### Impact Explanation
Each `selectGenesis` execution is a multi-table CTE with a correlated subquery and a full sort on `record_file`. On a node with a populated `record_file` table, this is a sequential-scan-class query. Sustained concurrent issuance (even at the Traefik default of 10 req/s per host) produces 10–20 DB queries per second with no caching or coalescing, directly raising DB CPU. Because the condition persists for the entire startup window (which can last minutes while the importer catches up), the attacker has a repeatable, sustained amplification primitive requiring no credentials.

### Likelihood Explanation
The Rosetta API is a public HTTP endpoint with no application-level authentication. The Traefik middleware (`inFlightReq`, `rateLimit`) is an optional Kubernetes deployment artifact — it is absent in bare-metal or Docker deployments and bypassable via distributed source IPs. The startup window is a predictable, observable event (the node returns `ErrNodeIsStarting` to callers, advertising its own vulnerability window). Any unprivileged actor who can reach the Rosetta port can trigger this.

### Recommendation
Move the entire query *inside* `sync.Once` so it executes at most once regardless of concurrency or failure:

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
    })
    // If once.Do already ran successfully, genesisBlock is set; if it failed,
    // reset once so the next caller retries (use a resettable once or a mutex+flag).
    ...
}
```

Because `sync.Once` cannot be retried after failure, the correct pattern is a mutex-guarded flag or `golang.org/x/sync/singleflight`, which also coalesces concurrent in-flight calls into a single DB round-trip.

### Proof of Concept
```bash
# During node startup (while /block/latest returns ErrNodeIsStarting):
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:<port>/block \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index":0}}' &
done
wait
# Observe: 50 concurrent selectGenesis queries hit the DB simultaneously.
# Repeat in a loop; DB CPU climbs proportionally with no server-side throttle.
```

Monitor with `pg_stat_activity` or `EXPLAIN ANALYZE` on `selectGenesis` to confirm N simultaneous executions. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rosetta/app/persistence/block.go (L49-72)
```go
	selectGenesis string = `with genesis as (
                              select consensus_timestamp as timestamp
                              from account_balance
                               where account_id = @treasury_entity_id
                               order by consensus_timestamp
                               limit 1
                            )
                            select
                              hash,
                              index,
                              case
                                when genesis.timestamp >= rf.consensus_start then genesis.timestamp + 1
                                else rf.consensus_start
                              end consensus_start,
                              coalesce((
                                select rf1.consensus_start-1
                                from record_file rf1
                                where rf1.index = rf.index + 1
                              ), consensus_end) as consensus_end
                            from record_file rf
                            join genesis
                              on rf.consensus_end > genesis.timestamp
                            order by rf.consensus_end
                            limit 1`
```

**File:** rosetta/app/persistence/block.go (L190-208)
```go
func (br *blockRepository) RetrieveLatest(ctx context.Context) (*types.Block, *rTypes.Error) {
	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectLatestWithIndex).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}

	if rb.Index < br.genesisBlock.Index {
		return nil, hErrors.ErrBlockNotFound
	}

	return rb.ToBlock(br.genesisBlock), nil
}
```

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
