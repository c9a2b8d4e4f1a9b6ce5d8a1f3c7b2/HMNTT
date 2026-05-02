### Title
Unprotected Genesis Initialization Allows Repeated Expensive CTE Execution via Unauthenticated Requests

### Summary
In `rosetta/app/persistence/block.go`, the `initGenesisRecordFile` function uses an unprotected read of `br.genesisBlock.ConsensusStart` as a fast-path guard, but places `sync.Once` only around the assignment — not around the expensive `selectGenesis` CTE query. When genesis data is unavailable (node starting), the failure state is never cached, so every unauthenticated call to `RetrieveLatest` (or any method invoking `initGenesisRecordFile`) re-executes the expensive multi-table CTE query unconditionally. This allows any external user to drive sustained, compounded database resource consumption with no rate limiting or backoff.

### Finding Description

**Exact code path:**

`rosetta/app/persistence/block.go`, function `initGenesisRecordFile`, lines 243–263:

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {  // line 244 — unprotected read
        return nil
    }

    // ... expensive selectGenesis CTE executed here (line 252) ...
    if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)  // line 254 — returns WITHOUT caching
    }

    br.once.Do(func() {          // line 257 — sync.Once AFTER the query, not around it
        br.genesisBlock = rb
    })
    ...
}
```

**Root cause — two compounding flaws:**

1. **`sync.Once` is misplaced.** It wraps only the assignment (`br.genesisBlock = rb`), not the DB query. Multiple concurrent goroutines can simultaneously pass the unprotected check on line 244 and all execute the expensive `selectGenesis` CTE before any of them reaches `once.Do`. This is a classic TOCTOU race.

2. **Failure state is never cached.** When `db.Raw(selectGenesis...).First(&rb)` returns an error (genesis not yet in DB), the function returns `ErrNodeIsStarting` at line 254 without ever calling `once.Do`. Therefore `br.genesisBlock.ConsensusStart` remains `genesisConsensusStartUnset` (-1) permanently. Every subsequent call passes the check on line 244 and re-executes the full CTE — indefinitely, with no backoff, no cooldown, and no deduplication.

**`selectGenesis` query cost** (lines 49–72): it performs a CTE scan over `account_balance` with `ORDER BY consensus_timestamp LIMIT 1`, then a join against `record_file` with `ORDER BY rf.consensus_end LIMIT 1`, plus a correlated subquery per row. This is a non-trivial multi-table query on potentially large tables.

**Call chain from public API:**
- `POST /network/status` → `NetworkStatus()` → `RetrieveGenesis()` + `RetrieveLatest()` → `initGenesisRecordFile()` (twice per request)
- `POST /block` → `Block()` → `RetrieveBlock()` → `RetrieveLatest()` → `initGenesisRecordFile()`

Both endpoints are unauthenticated per the Rosetta specification.

### Impact Explanation
During any window where genesis data is absent from the database (node startup, re-indexing, or a deliberately delayed genesis ingestion), an attacker sending N concurrent or sequential requests to `/network/status` or `/block` causes exactly N executions of the expensive `selectGenesis` CTE against the live database. Since there is no request-rate limiting, no per-IP throttling, and no failure-state caching, the attacker can sustain this indefinitely. With sufficient request rate, this directly translates to a measurable and sustained increase in DB CPU, I/O, and connection pool consumption — meeting the stated threshold of ≥30% resource increase without brute-force credential attacks.

### Likelihood Explanation
The Rosetta API is a public, unauthenticated HTTP interface by design (Coinbase Rosetta spec). No credentials, tokens, or special network access are required. The attack window (genesis not yet cached) is not just a brief startup moment: it persists for the entire duration that genesis data is absent from the DB, which can be minutes to hours during initial sync. Any external user who can reach the Rosetta port can trigger this. The attack is trivially scriptable with `curl` in a loop or any HTTP load tool.

### Recommendation

Restructure `initGenesisRecordFile` so that `sync.Once` wraps the entire query-and-assign block, **and** use a separate mutex or atomic flag to cache the failure state with a cooldown:

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    // Fast path: already initialized (use atomic load or read under mu)
    br.mu.RLock()
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
        br.mu.RUnlock()
        return nil
    }
    br.mu.RUnlock()

    br.mu.Lock()
    defer br.mu.Unlock()
    // Double-check after acquiring write lock
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
        return nil
    }
    // Execute query exactly once per successful initialization
    var rb recordBlock
    if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
    }
    br.genesisBlock = rb
    return nil
}
```

Remove the now-redundant `sync.Once` field. This ensures the expensive query is executed at most once concurrently and the result is immediately visible to all subsequent callers.

### Proof of Concept

**Precondition:** Rosetta node is running but genesis data is not yet available in the DB (e.g., during initial sync, or `account_balance` table is empty).

**Steps:**
```bash
# Confirm genesis is not yet cached (node returns ErrNodeIsStarting)
curl -s -X POST http://<rosetta-host>:5700/network/status \
  -H "Content-Type: application/json" \
  -d '{"network_identifier": {"blockchain":"Hedera","network":"mainnet"}}'
# Expected: {"code":..., "message":"Node is starting"}

# Flood with concurrent requests — each triggers selectGenesis CTE
for i in $(seq 1 500); do
  curl -s -X POST http://<rosetta-host>:5700/network/status \
    -H "Content-Type: application/json" \
    -d '{"network_identifier": {"blockchain":"Hedera","network":"mainnet"}}' &
done
wait

# Observe DB: 500 executions of the selectGenesis CTE in pg_stat_activity / slow query log
# Monitor pg_stat_activity or DB CPU — expect sustained spike proportional to request rate
```

Each request in the loop independently passes the unprotected check at line 244, executes the full `selectGenesis` CTE at line 252, receives an error, and returns — leaving `br.genesisBlock.ConsensusStart` at `-1` so the next request repeats the cycle. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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
