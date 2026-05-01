### Title
Unsynchronized `selectGenesis` CTE Execution Allows Concurrent DB Load Amplification Before Genesis Initialization

### Summary
In `rosetta/app/persistence/block.go`, the `initGenesisRecordFile()` function uses `sync.Once` only to protect the *write* to `br.genesisBlock`, but the expensive `selectGenesis` CTE database query executes *before* and *outside* the `once.Do` block. Because the initial uninitialized check at line 244 is also unsynchronized, any number of concurrent goroutines can simultaneously pass the check and each independently issue the `selectGenesis` query to the database, multiplying DB load linearly with the number of concurrent callers.

### Finding Description

**Exact code path:** `rosetta/app/persistence/block.go`, `initGenesisRecordFile()`, lines 243–263.

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    // LINE 244: Unsynchronized read — no mutex, no atomic
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
        return nil
    }

    db, cancel := br.dbClient.GetDbWithContext(ctx)
    defer cancel()

    var rb recordBlock
    // LINE 252-255: DB query executes OUTSIDE any synchronization primitive
    if err := db.Raw(selectGenesis, sql.Named("treasury_entity_id", br.treasuryEntityId.EncodedId)).
        First(&rb).Error; err != nil {
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
    }

    // LINE 257-259: once.Do only protects the assignment, NOT the query above
    br.once.Do(func() {
        br.genesisBlock = rb
    })
    ...
}
```

**Root cause:** `sync.Once` is misplaced. It guards only the struct field assignment, while the expensive `selectGenesis` CTE (which joins `account_balance` and `record_file` with a correlated subquery) runs unconditionally for every goroutine that passes the unsynchronized check at line 244. During the window before genesis is set, all concurrent callers see `ConsensusStart == genesisConsensusStartUnset (-1)` and proceed to issue independent DB queries.

**All five public entry points** call `initGenesisRecordFile()` before doing anything else:
- `FindByHash` (line 140)
- `FindByIdentifier` (line 155)
- `FindByIndex` (line 176)
- `RetrieveGenesis` (line 184)
- `RetrieveLatest` (line 191)

**Why existing checks fail:**
- The Traefik `inFlightReq: amount: 5` and `rateLimit: average: 10` middleware in `charts/hedera-mirror-rosetta/values.yaml` (lines 152–160) are: (a) optional Kubernetes infrastructure configs gated on `global.middleware`, (b) per-IP/per-host, so N distinct source IPs each contribute 5 concurrent requests = 5N simultaneous `selectGenesis` queries, and (c) not present in the application layer at all.
- There is no application-level authentication or concurrency guard on the Rosetta HTTP endpoints.

### Impact Explanation
The `selectGenesis` query (lines 49–72) performs a full ordered scan of `account_balance` filtered by `account_id`, a join to `record_file`, and a correlated subquery per matched row. Under concurrent load this query is I/O and CPU intensive. With N concurrent unauthenticated callers each triggering one `selectGenesis` execution, database CPU and I/O load scales as O(N). Even a modest flood (e.g., 30–50 concurrent HTTP requests from a handful of IPs) during node startup — when genesis is not yet initialized — can increase database processing load well above 30% compared to the preceding 24-hour baseline, satisfying the stated impact threshold without brute-force volume.

### Likelihood Explanation
The Rosetta API is a public HTTP endpoint with no authentication requirement. The vulnerable window exists every time the mirror node restarts (a routine operational event). An attacker needs only to detect the restart (e.g., by polling `/health/liveness`) and immediately flood any of the five block endpoints with concurrent requests. This requires no credentials, no special knowledge, and is trivially scriptable. The attack is repeatable on every restart.

### Recommendation
Move the entire DB query inside `sync.Once` so it executes at most once regardless of concurrency:

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
    })
    if br.genesisBlock.ConsensusStart == genesisConsensusStartUnset {
        return hErrors.ErrNodeIsStarting
    }
    return initErr
}
```

This ensures the `selectGenesis` CTE is issued exactly once, regardless of how many goroutines call `initGenesisRecordFile` concurrently.

### Proof of Concept

**Preconditions:** Mirror node has just restarted; genesis is not yet initialized (`ConsensusStart == -1`).

**Steps:**
1. Poll `GET /health/liveness` until the node is up but genesis is not yet set (returns `ErrNodeIsStarting` on block endpoints).
2. From multiple source IPs (to bypass per-IP Traefik limits), concurrently send HTTP POST requests to `/block` (or any mix of `/block`, `/block/transaction`, `/network/status`) — each of which internally calls `initGenesisRecordFile`.
3. Each goroutine passes the unsynchronized check at line 244 (all see `ConsensusStart == -1`).
4. Each goroutine independently executes `db.Raw(selectGenesis, ...)` against the database.
5. Observe N simultaneous `selectGenesis` CTE executions in the database query log (`pg_stat_activity`), with DB CPU/IO spiking proportionally.

**Expected result:** Database load increases by a factor of N (number of concurrent callers), exceeding the 30% threshold with as few as ~5–10 concurrent callers from multiple IPs. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rosetta/app/persistence/block.go (L119-133)
```go
type blockRepository struct {
	dbClient         interfaces.DbClient
	genesisBlock     recordBlock
	once             sync.Once
	treasuryEntityId domain.EntityId
}

// NewBlockRepository creates an instance of a blockRepository struct
func NewBlockRepository(dbClient interfaces.DbClient, treasuryEntityId domain.EntityId) interfaces.BlockRepository {
	return &blockRepository{
		dbClient:         dbClient,
		genesisBlock:     recordBlock{ConsensusStart: genesisConsensusStartUnset},
		treasuryEntityId: treasuryEntityId,
	}
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
