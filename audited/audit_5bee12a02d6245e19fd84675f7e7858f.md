### Title
Broken `sync.Once` Caching in `initGenesisRecordFile` Enables Sustained DB CPU Exhaustion via Repeated Expensive Correlated Subquery

### Summary
`initGenesisRecordFile()` in `rosetta/app/persistence/block.go` uses `sync.Once` only on the success path. When the DB returns any error, `once.Do` is never called and `br.genesisBlock.ConsensusStart` remains at the sentinel value `-1`. Every subsequent API call re-checks the sentinel, finds it unset, and re-executes the expensive `selectGenesis` correlated subquery against the live DB. An unprivileged attacker who can sustain DB connection exhaustion (via concurrent unauthenticated API requests) prevents the cache from ever being populated, forcing every request to hammer the DB with the costly CTE+correlated-subquery indefinitely.

### Finding Description

**Exact code path:** `rosetta/app/persistence/block.go`, `initGenesisRecordFile()`, lines 243–263.

```
243: func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
244:     if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
245:         return nil                          // fast-path: only reachable after once.Do succeeds
246:     }
247:
248:     db, cancel := br.dbClient.GetDbWithContext(ctx)
249:     defer cancel()
250:
251:     var rb recordBlock
252:     if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {
253:         return handleDatabaseError(err, hErrors.ErrNodeIsStarting)  // ← returns WITHOUT calling once.Do
254:     }
255:
256:     br.once.Do(func() {          // ← only reached on success; never called when DB errors
257:         br.genesisBlock = rb
258:     })
259:     ...
263: }
```

**Root cause:** The `sync.Once` guard is placed *after* the fallible DB call. On any DB error the function returns at line 254, leaving `br.genesisBlock.ConsensusStart == genesisConsensusStartUnset` (-1). The guard check at line 244 therefore evaluates to `false` on every future invocation, unconditionally re-issuing the `selectGenesis` query. The `sync.Once` field is never consumed, so it provides zero protection against repeated execution under error conditions.

**All five public methods gate on this function:**
- `FindByHash` (line 140)
- `FindByIdentifier` (line 155)
- `FindByIndex` (line 176)
- `RetrieveGenesis` (line 184)
- `RetrieveLatest` (line 191)

**The `selectGenesis` query (lines 49–72) is expensive:**
- CTE scanning `account_balance` ordered by `consensus_timestamp`
- Join against `record_file`
- Correlated subquery per row to compute `consensus_end`

**Exploit flow:**

1. Attacker opens N concurrent unauthenticated HTTP connections to the Rosetta API (any block endpoint).
2. Each request calls `initGenesisRecordFile()`. With N exceeding the DB connection pool size, some requests fail to acquire a connection → `handleDatabaseError` returns `ErrDatabaseError` without calling `once.Do`.
3. Requests that do acquire connections execute `selectGenesis`. If the DB is already under load from the flood, these queries time out or error as well → same early-return path.
4. `br.genesisBlock` is never populated. The sentinel remains `-1`.
5. Every new request (attacker or legitimate) re-enters the expensive query path.
6. Feedback loop: more concurrent requests → more DB CPU → more timeouts → more failures → cache never set → more expensive queries per request.

**Existing checks are insufficient:**
- `sync.Once` is misused: it is only invoked on the success branch, not on the attempt itself.
- The sentinel check at line 244 is an unsynchronized read of a struct field written by `once.Do` — a data race under Go's memory model, but more critically it is only `true` after a successful write that never happens under sustained errors.
- No rate limiting, circuit breaker, backoff, or maximum retry count exists anywhere in this path.

### Impact Explanation
Every unauthenticated API call to any block-related Rosetta endpoint triggers a full CTE + correlated subquery against `account_balance` and `record_file`. Under sustained attack, the DB CPU is continuously saturated by this single query pattern. Because the Rosetta node is part of the Hedera/Hiero mirror-node infrastructure (serving consensus-layer block data), DB exhaustion here degrades or halts block data availability for all downstream consumers, including exchanges and validators that rely on Rosetta for balance and transaction queries.

### Likelihood Explanation
The Rosetta API requires no authentication. The attacker needs only HTTP access and enough concurrency to keep the DB connection pool saturated — achievable with a modest botnet or even a single machine with high concurrency. The attack is repeatable and self-sustaining: as long as the attacker maintains the flood, the cache is never populated and the expensive query fires on every request. No special knowledge of the system internals is required beyond knowing the public Rosetta block endpoints.

### Recommendation
Move `once.Do` to wrap the entire initialization attempt, including the DB query, so that the `Once` is consumed on the first attempt regardless of success or failure. For retry-on-failure semantics (desirable here, since the node may genuinely be starting up), replace `sync.Once` with an explicit mutex + boolean flag pattern:

```go
br.mu.Lock()
defer br.mu.Unlock()
if br.genesisInitialized {
    return nil
}
// ... execute selectGenesis ...
// on success:
br.genesisBlock = rb
br.genesisInitialized = true
```

Additionally, add a short-circuit backoff (e.g., exponential backoff with a cap) so that transient DB errors do not result in unbounded per-request query retries.

### Proof of Concept

```bash
# 1. Confirm the Rosetta API is unauthenticated and accessible
curl http://<rosetta-host>:5700/network/list

# 2. Flood the block endpoint with high concurrency to exhaust the DB pool
#    (adjust -c to exceed the configured DB max_connections)
ab -n 100000 -c 200 -p block_request.json -T application/json \
   http://<rosetta-host>:5700/block

# block_request.json:
# {"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
#  "block_identifier":{"index":1}}

# 3. While the flood is running, observe DB CPU via pg_stat_activity:
psql -c "SELECT count(*), query FROM pg_stat_activity
         WHERE query LIKE '%account_balance%'
         GROUP BY query;"
# Expected: hundreds of concurrent 'selectGenesis' CTE queries

# 4. Stop the flood; observe that DB CPU drops immediately,
#    confirming the cache was never populated and every request
#    was executing the expensive query.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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
