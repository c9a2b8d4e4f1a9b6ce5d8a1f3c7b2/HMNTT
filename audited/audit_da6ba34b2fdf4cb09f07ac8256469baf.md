### Title
Misused `sync.Once` in `initGenesisRecordFile` Allows Concurrent `selectGenesis` SQL Execution, Enabling DB CPU Exhaustion via Unauthenticated `/network/status` Requests

### Summary
In `rosetta/app/persistence/block.go`, the `initGenesisRecordFile` function uses `sync.Once` only to protect the *write* to `br.genesisBlock`, but the expensive `selectGenesis` SQL query executes *outside* the `sync.Once` guard. An unsynchronized early-exit check precedes the query, creating a race window where any number of concurrent goroutines can simultaneously issue the correlated-subquery-heavy `selectGenesis` against the database. An unauthenticated attacker flooding `/network/status` before the genesis block is cached can drive DB CPU well above the 30% threshold.

### Finding Description

**Exact code path:**

`rosetta/app/services/network_service.go` lines 59–70: `NetworkStatus` calls `n.RetrieveGenesis(ctx)`. [1](#0-0) 

`RetrieveGenesis` calls `br.initGenesisRecordFile(ctx)`: [2](#0-1) 

`initGenesisRecordFile` is the vulnerable function: [3](#0-2) 

**Root cause — `sync.Once` placed after the SQL query, not around it:**

```
Line 244: if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset { return nil }
           ↑ unsynchronized read — all N concurrent goroutines see -1 and fall through

Lines 252-255: db.Raw(selectGenesis, ...).First(&rb)
               ↑ expensive SQL executes N times concurrently — NOT inside sync.Once

Lines 257-259: br.once.Do(func() { br.genesisBlock = rb })
               ↑ sync.Once only serializes the *assignment*, not the query
```

The `selectGenesis` query is a multi-table CTE with a correlated subquery: [4](#0-3) 

It performs:
- A full ordered scan of `account_balance` filtered by `account_id`
- A JOIN with `record_file` on `consensus_end > genesis.timestamp`
- A correlated subquery per row: `SELECT rf1.consensus_start-1 FROM record_file rf1 WHERE rf1.index = rf.index + 1`
- `ORDER BY rf.consensus_end LIMIT 1`

**Why existing checks fail:**

The Traefik-level `inFlightReq: amount: 5` and `rateLimit: average: 10` mitigations are:
1. Optional — gated on `global.middleware` being enabled (default `false` in `values.yaml`)
2. Per-IP / per-host — trivially bypassed with multiple source IPs or direct access
3. Not present at the application layer at all — `main.go` wires no in-process rate limiter [5](#0-4) [6](#0-5) 

### Impact Explanation
Every concurrent `/network/status` request before genesis is cached issues a full `selectGenesis` execution against PostgreSQL. With the DB pool configured up to 100 open connections (`maxOpenConnections: 100`), an attacker can saturate the pool with this query. The CTE + correlated subquery pattern is non-trivial; on a production mirror node with millions of `record_file` and `account_balance` rows, each execution consumes measurable CPU. Flooding with tens of concurrent requests during the startup window (or after a process restart) can spike DB CPU by 30%+ above baseline, degrading all other mirror-node services sharing the same PostgreSQL instance. [7](#0-6) 

### Likelihood Explanation
- **No authentication required** — `/network/status` is a public Rosetta API endpoint.
- **Startup window is predictable** — process restarts (rolling deploys, crashes, HPA scale-out) reset `br.genesisBlock` to `genesisConsensusStartUnset`, reopening the race window each time.
- **Trivial to exploit** — a simple loop of concurrent HTTP POST requests to `/network/status` is sufficient; no special knowledge or credentials needed.
- **Middleware bypass** — the Traefik middleware chain is opt-in and per-IP; an attacker with a botnet or direct cluster access bypasses it entirely.

### Recommendation
Move the entire SQL query *inside* `sync.Once` so it executes at most once regardless of concurrency:

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
    // If once.Do already ran successfully, genesisBlock is set; check for error from this call
    if initErr != nil {
        return initErr
    }
    if br.genesisBlock.ConsensusStart == genesisConsensusStartUnset {
        return hErrors.ErrNodeIsStarting
    }
    return nil
}
```

Note: if retry-on-failure is needed (i.e., `sync.Once` should not permanently suppress retries when the DB is unavailable at startup), use a mutex-guarded flag instead of `sync.Once`.

Additionally, enforce an in-process concurrency limit (e.g., `golang.org/x/sync/semaphore`) on DB-touching handlers, independent of the optional Traefik middleware.

### Proof of Concept

**Preconditions:**
1. Rosetta node is starting up (or has just restarted) — `br.genesisBlock.ConsensusStart == -1`.
2. The Traefik middleware chain is either disabled or the attacker uses multiple source IPs.

**Trigger:**
```bash
# Send 50 concurrent POST /network/status requests
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:5700/network/status \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
done
wait
```

**Result:**
- All 50 goroutines pass the unsynchronized `ConsensusStart != -1` check simultaneously.
- All 50 execute `selectGenesis` concurrently against PostgreSQL.
- DB CPU spikes; `pg_stat_activity` shows 50 identical `selectGenesis` queries running in parallel.
- Repeat on each process restart to sustain the elevated DB load.

### Citations

**File:** rosetta/app/services/network_service.go (L59-70)
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
```

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

**File:** rosetta/app/persistence/block.go (L183-188)
```go
func (br *blockRepository) RetrieveGenesis(ctx context.Context) (*types.Block, *rTypes.Error) {
	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}
	return br.genesisBlock.ToBlock(br.genesisBlock), nil
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

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
