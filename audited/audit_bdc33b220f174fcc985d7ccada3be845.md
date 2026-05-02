### Title
Race Window in `initGenesisRecordFile()` Allows N Concurrent Goroutines to Each Execute the Expensive `selectGenesis` CTE Query Before `sync.Once` Fires

### Summary
In `rosetta/app/persistence/block.go`, the function `initGenesisRecordFile()` uses an unsynchronized read of `br.genesisBlock.ConsensusStart` as an early-exit guard, but the `sync.Once` is placed only around the *assignment* — not around the database query. Any number of concurrent goroutines can pass the guard simultaneously during the startup window and each independently execute the expensive `selectGenesis` CTE query, multiplying database load by N without any rate limiting or authentication requirement.

### Finding Description
**Exact code path:**

`rosetta/app/persistence/block.go`, function `initGenesisRecordFile()`, lines 243–263:

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {  // line 244 — unsynchronized plain read
        return nil
    }
    // ← race window: N goroutines all pass here simultaneously

    db, cancel := br.dbClient.GetDbWithContext(ctx)
    defer cancel()

    var rb recordBlock
    if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {  // lines 252-255 — N queries fire
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
    }

    br.once.Do(func() {       // line 257 — sync.Once only guards the write
        br.genesisBlock = rb  // line 258 — only one goroutine sets this
    })
    ...
}
```

**Root cause and failed assumption:**

The developer assumed `sync.Once` would prevent duplicate work. It does not — `sync.Once` only serializes the *assignment* at line 258. The DB query at lines 252–255 is entirely outside `sync.Once`. The early-exit guard at line 244 is a plain, unsynchronized read of an `int64` struct field with no mutex, atomic, or memory barrier. Under Go's memory model this is a data race, and practically it means every goroutine that reads `ConsensusStart == -1` before any `br.once.Do()` write completes will proceed to issue its own copy of the `selectGenesis` query.

**`selectGenesis` query cost** (lines 49–72):
```sql
with genesis as (
  select consensus_timestamp from account_balance
  where account_id = @treasury_entity_id
  order by consensus_timestamp limit 1
)
select hash, index, ...,
  (select rf1.consensus_start-1 from record_file rf1 where rf1.index = rf.index + 1)
from record_file rf
join genesis on rf.consensus_end > genesis.timestamp
order by rf.consensus_end limit 1
```
This CTE touches `account_balance` with `ORDER BY`, joins `record_file`, and runs a correlated subquery — a non-trivial read on large tables.

**Why existing checks fail:**
- The `sync.Once` at line 257 only prevents duplicate *writes*; it does not prevent duplicate *queries*.
- There is no mutex, `sync.RWMutex`, or `atomic.Load` protecting the read at line 244.
- There is no HTTP-level rate limiting or authentication on the Rosetta block endpoints (`FindByHash`, `FindByIdentifier`, `FindByIndex`, `RetrieveGenesis`, `RetrieveLatest`) — all five call `initGenesisRecordFile()`. [1](#0-0) 

### Impact Explanation
During the startup window (from process start until the first `br.once.Do()` write completes and becomes visible), an attacker sending N concurrent HTTP requests to any of the five public block endpoints causes N copies of the `selectGenesis` CTE to execute simultaneously against the database. With N=50 concurrent connections (well within HTTP client capability), the database receives 50× the expected genesis-initialization query load. On a large mirror node database with millions of `account_balance` and `record_file` rows, this can saturate I/O, exhaust connection pool slots, and delay or crash the node's startup — satisfying the "≥30% resource increase" threshold without any brute-force credential guessing. [2](#0-1) [3](#0-2) 

### Likelihood Explanation
The Rosetta API is an unauthenticated HTTP service (see `main.go` lines 220–227 — no auth middleware is applied before the router). Any external client with network access can send concurrent requests. The attacker only needs to target the startup window, which is predictable (e.g., after a known deployment or restart event). The exploit requires no credentials, no special protocol knowledge, and no brute force — just a standard HTTP concurrency tool (`wrk`, `ab`, `hey`). The window repeats on every node restart. [4](#0-3) 

### Recommendation
Move the entire DB query inside `sync.Once` so that at most one goroutine ever executes `selectGenesis`, regardless of concurrency:

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

This ensures the DB query executes exactly once. Additionally, protect the early-exit read with `sync/atomic` or a `sync.RWMutex` to eliminate the Go memory model data race on `br.genesisBlock.ConsensusStart`. [5](#0-4) 

### Proof of Concept
**Preconditions:**
1. Deploy the mirror node Rosetta service against a populated database.
2. Restart the service (so `br.genesisBlock.ConsensusStart` resets to `-1`).

**Trigger:**
```bash
# Send 100 concurrent requests to /block endpoint immediately after restart
hey -n 100 -c 100 -m POST \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"block_identifier":{"index":0}}' \
  http://<rosetta-host>:<port>/block
```

**Observe:**
- In the database slow-query log or `pg_stat_activity`, observe up to 100 simultaneous executions of the `selectGenesis` CTE query during the startup window.
- Database CPU/IO metrics spike proportionally to N concurrent requests.
- `sync.Once` fires for only one goroutine's *write*, but all 100 DB queries have already been dispatched. [6](#0-5)

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

**File:** rosetta/app/persistence/block.go (L119-124)
```go
type blockRepository struct {
	dbClient         interfaces.DbClient
	genesisBlock     recordBlock
	once             sync.Once
	treasuryEntityId domain.EntityId
}
```

**File:** rosetta/app/persistence/block.go (L135-145)
```go
func (br *blockRepository) FindByHash(ctx context.Context, hash string) (*types.Block, *rTypes.Error) {
	if hash == "" {
		return nil, hErrors.ErrInvalidArgument
	}

	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	return br.findBlockByHash(ctx, hash)
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

**File:** rosetta/main.go (L217-227)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```
