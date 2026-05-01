### Title
Misplaced `sync.Once` in `initGenesisRecordFile` Allows Thundering Herd of Concurrent `selectGenesis` SQL Queries

### Summary
In `rosetta/app/persistence/block.go`, the `initGenesisRecordFile()` function uses `sync.Once` only to guard the *assignment* of `br.genesisBlock`, not the expensive `selectGenesis` SQL query that precedes it. An unsynchronized pre-check allows N concurrent goroutines to all pass the guard and each independently fire the `selectGenesis` query against the database. An unprivileged external attacker can exploit this by flooding `/network/status` with concurrent requests during startup (or any period where genesis is uninitialized), exhausting the database connection pool and starving transaction-processing queries.

### Finding Description

**Exact code path:** `rosetta/app/persistence/block.go`, `initGenesisRecordFile()`, lines 243–263.

```
243: func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
244:     if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {   // ← unsynchronized read
245:         return nil
246:     }
247:
248:     db, cancel := br.dbClient.GetDbWithContext(ctx)
249:     defer cancel()
250:
251:     var rb recordBlock
252:     if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {  // ← SQL fires here, BEFORE once.Do
253:         return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
254:     }
255:
256:     br.once.Do(func() {                                                  // ← once.Do only guards the write
257:         br.genesisBlock = rb
258:     })
259:     ...
263: }
```

**Root cause:** `sync.Once` is placed *after* the SQL query, so it only prevents duplicate writes to `br.genesisBlock`. It does nothing to prevent duplicate executions of the `selectGenesis` query. The pre-check on line 244 is an unsynchronized read of a struct field that may be concurrently written on line 258 — a Go data race. Any number of goroutines that arrive before the first `once.Do` completes will all pass the check and all execute the query.

**Failed assumption:** The developer assumed `once.Do` would serialize the entire initialization. It only serializes the assignment.

**Exploit flow:**
1. Attacker sends a burst of concurrent `POST /network/status` requests (no authentication required — public Rosetta API).
2. Each request reaches `NetworkStatus()` → `RetrieveGenesis()` → `blockRepo.RetrieveGenesis()` → `initGenesisRecordFile()`.
3. All goroutines read `br.genesisBlock.ConsensusStart == -1` (unset) and proceed past the guard.
4. All goroutines concurrently execute the `selectGenesis` CTE query (lines 49–72), which joins `account_balance` and `record_file` with ordering and a correlated subquery.
5. `once.Do` fires for only one goroutine's result; the rest discard their result but the DB work is already done.
6. If the genesis query itself fails (e.g., DB is slow/overloaded), `once.Do` is never called, `br.genesisBlock.ConsensusStart` stays at `-1`, and *every subsequent request* re-executes the query — making the thundering herd persistent, not just a startup race. [1](#0-0) [2](#0-1) 

### Impact Explanation

The `selectGenesis` query (lines 49–72) is a multi-table CTE with a correlated subquery and `ORDER BY` — not a trivial point lookup. Under a flood of concurrent requests, the database connection pool is exhausted by simultaneous executions of this query. This starves all other queries, including transaction-processing queries that rely on `record_file` and `account_balance`. The result is a full denial of service of the Rosetta API node and degraded performance of the underlying mirror node database, matching the "total network shutdown" classification. The persistent failure path (genesis query keeps failing → every request re-queries) means the attack can be sustained indefinitely. [3](#0-2) 

### Likelihood Explanation

- **No authentication required:** `/network/status` is a public, unauthenticated Rosetta endpoint.
- **Trivial to trigger:** A single attacker with a basic HTTP load tool (e.g., `wrk`, `ab`, `hey`) can send thousands of concurrent requests.
- **Window of vulnerability:** The window is widest at startup, but the persistent failure path means the window never closes if the DB is under stress — the attacker can induce the failure condition by causing the initial queries to time out, then sustain the attack.
- **No rate limiting visible** in the service layer. [4](#0-3) 

### Recommendation

Move the entire SQL query *inside* `once.Do` so that `sync.Once` serializes both the query and the assignment:

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

Note: if the query can fail and must be retried, `sync.Once` is insufficient (it will not re-run on failure). In that case, use a mutex with a double-checked lock pattern, or a dedicated initialization goroutine with a channel/condition variable. Also eliminate the unsynchronized pre-check or replace it with an atomic load. [5](#0-4) 

### Proof of Concept

```bash
# Requires: running hiero-mirror-node rosetta service at startup
# (or with DB under load so genesis query is slow)

# Send 500 concurrent /network/status requests
hey -n 500 -c 500 -m POST \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  http://<rosetta-host>:5700/network/status

# Expected result:
# - DB shows 500 simultaneous executions of the selectGenesis CTE query
# - Connection pool exhausted; other queries (transaction processing) time out
# - Subsequent legitimate requests receive ErrNodeIsStarting or ErrDatabaseError
# - If genesis query times out under load, condition persists across restarts of the attack
``` [1](#0-0)

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

**File:** rosetta/app/services/network_service.go (L59-88)
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

	currentBlock, err := n.RetrieveLatest(ctx)
	if err != nil {
		return nil, err
	}

	peers, err := n.addressBookEntryRepo.Entries(ctx)
	if err != nil {
		return nil, err
	}

	return &rTypes.NetworkStatusResponse{
		CurrentBlockIdentifier: currentBlock.GetRosettaBlockIdentifier(),
		CurrentBlockTimestamp:  currentBlock.GetTimestampMillis(),
		GenesisBlockIdentifier: genesisBlock.GetRosettaBlockIdentifier(),
		Peers:                  peers.ToRosetta(),
	}, nil
}
```
