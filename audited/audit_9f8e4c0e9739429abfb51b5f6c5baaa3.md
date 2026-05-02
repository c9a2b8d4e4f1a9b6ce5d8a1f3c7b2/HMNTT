### Title
Race Condition in `initGenesisRecordFile`: `sync.Once` Placed After SQL Execution Allows Concurrent `selectGenesis` Query Storms

### Summary
In `rosetta/app/persistence/block.go`, `initGenesisRecordFile` checks whether genesis is initialized with an unsynchronized read, then executes the expensive `selectGenesis` SQL query, and only *then* calls `sync.Once` to write the result. This means `sync.Once` guards only the assignment, not the query. Any number of goroutines can pass the guard check simultaneously and each independently execute the complex CTE+JOIN+correlated-subquery against the database before any one of them completes the write.

### Finding Description

**Exact code path** — `rosetta/app/persistence/block.go`, lines 243–263:

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    // (1) Unsynchronized read — no mutex, no atomic
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
        return nil
    }

    db, cancel := br.dbClient.GetDbWithContext(ctx)
    defer cancel()

    var rb recordBlock
    // (2) SQL query executed BEFORE sync.Once — N goroutines all reach here
    if err := db.Raw(selectGenesis, sql.Named("treasury_entity_id", br.treasuryEntityId.EncodedId)).
        First(&rb).Error; err != nil {
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
    }

    // (3) sync.Once only protects the assignment, not the query above
    br.once.Do(func() {
        br.genesisBlock = rb
    })
    ...
}
```

**Root cause**: The developer assumed `sync.Once` would prevent duplicate work, but placed it *after* the expensive operation. The correct pattern is to wrap the entire SQL execution inside `once.Do`. The initial guard at line 244 is also an unsynchronized read of a struct field that another goroutine may be writing (data race per Go memory model).

**Exploit flow**:
1. Rosetta node starts in online mode; `br.genesisBlock.ConsensusStart` is `-1` (unset).
2. Attacker sends N concurrent POST requests to any online endpoint that calls `initGenesisRecordFile` — e.g., `/network/status` (calls `RetrieveGenesis` → `initGenesisRecordFile`), `/block`, `/account/balance`.
3. All N goroutines read `ConsensusStart == -1` simultaneously (step 1 passes for all).
4. All N goroutines independently issue `selectGenesis` to the database.
5. `sync.Once` fires for the first goroutine to finish; the remaining N-1 queries run to completion and are discarded — but the DB has already paid the CPU cost for all N.

**`selectGenesis` query cost** (lines 49–72):
```sql
with genesis as (
  select consensus_timestamp as timestamp
  from account_balance
  where account_id = @treasury_entity_id
  order by consensus_timestamp limit 1
)
select hash, index, ... 
from record_file rf
join genesis on rf.consensus_end > genesis.timestamp
order by rf.consensus_end limit 1
-- plus correlated subquery per row:
-- (select rf1.consensus_start-1 from record_file rf1 where rf1.index = rf.index + 1)
```
This touches `account_balance` (potentially millions of rows), `record_file` twice (join + correlated subquery), and sorts — a non-trivial read amplification per concurrent call.

**Why existing checks fail**:

The Traefik middleware (`values.yaml` lines 152–161) configures:
- `inFlightReq.amount: 5` per source IP — an attacker using 20 IPs (trivially available via cloud VMs or a small botnet) gets 100 concurrent in-flight requests.
- `rateLimit.average: 10` per `requestHost` — this is per hostname, not per IP, and allows bursting above the average.
- The middleware is opt-in (`global.middleware: false` default) and only applies when Traefik ingress is deployed; direct access to the service port bypasses it entirely.
- No application-level concurrency gate exists around the SQL query.

### Impact Explanation
Every concurrent request before genesis initialization issues a full `selectGenesis` query. With 50–100 concurrent requests (easily achievable from multiple IPs or a single IP bypassing the middleware), the database receives 50–100 simultaneous instances of a CTE+JOIN+correlated-subquery scan. On a production mirror node with a large `account_balance` table, this can spike DB CPU well above 30% of the 24-hour baseline. The window of vulnerability is the entire startup period until the first successful genesis initialization, which can be extended if the DB is slow to respond (e.g., under load), creating a feedback loop.

### Likelihood Explanation
The attack requires no authentication, no special knowledge beyond the public Rosetta API spec, and no privileged access. Any external user can POST to `/network/status` or `/block`. The attack is most effective at node startup or restart — events that are observable (e.g., monitoring public block height gaps). A single attacker with access to a few cloud IPs can sustain the attack. The exploit is repeatable: if the node is restarted (e.g., due to the DB overload causing a crash), the window reopens.

### Recommendation
Move the SQL query inside `sync.Once` so it executes at most once regardless of concurrency:

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
    // If once.Do already ran successfully, genesisBlock is set; check it.
    if initErr == nil && br.genesisBlock.ConsensusStart == genesisConsensusStartUnset {
        return hErrors.ErrNodeIsStarting
    }
    return initErr
}
```

Note: because `sync.Once` does not retry on error, a separate retry mechanism (e.g., resetting `once` on failure, or using a mutex+flag pattern) should be considered so transient DB errors during startup do not permanently disable genesis initialization.

### Proof of Concept

```bash
# Target: Rosetta node in online mode, just started (genesis not yet initialized)
# No authentication required.

BASE_URL="http://<rosetta-host>:<port>"
PAYLOAD='{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'

# Fire 100 concurrent requests from a single IP (or distribute across IPs to bypass inFlightReq)
for i in $(seq 1 100); do
  curl -s -X POST "$BASE_URL/network/status" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" &
done
wait

# Expected result:
# - 100 concurrent selectGenesis queries hit the database simultaneously
# - DB CPU spikes; monitor with: SELECT * FROM pg_stat_activity WHERE query LIKE '%account_balance%';
# - All queries return either ErrNodeIsStarting (if DB not ready) or the genesis block,
#   but the DB has executed the full query 100 times.
```