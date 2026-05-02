### Title
Misplaced `sync.Once` in `initGenesisRecordFile` Enables DB Connection Pool Exhaustion DoS During Network Partition

### Summary
`initGenesisRecordFile` in `rosetta/app/persistence/block.go` uses `sync.Once` only to guard the assignment of `genesisBlock`, not the database query itself. When the database is unreachable (network partition), the query fails, `once.Do` never fires, and `genesisBlock.ConsensusStart` remains at the sentinel value `-1`. Every subsequent unauthenticated request re-enters the function, acquires a connection from the bounded pool via `GetDbWithContext`, and holds it for up to `statementTimeout` seconds — allowing an attacker to exhaust all 100 default pool connections and deny service to legitimate users.

### Finding Description
**Exact code path:**

In `rosetta/app/persistence/block.go`, `initGenesisRecordFile` (lines 243–263):

```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {  // line 244 — unprotected read
        return nil
    }

    db, cancel := br.dbClient.GetDbWithContext(ctx)  // line 248 — acquires pool connection
    defer cancel()

    var rb recordBlock
    if err := db.Raw(selectGenesis, ...).First(&rb).Error; err != nil {
        return handleDatabaseError(err, hErrors.ErrNodeIsStarting)  // line 254 — returns WITHOUT setting genesisBlock
    }

    br.once.Do(func() {          // line 257 — only reached on SUCCESS
        br.genesisBlock = rb
    })
    ...
}
```

**Root cause:** `sync.Once` is placed after the DB query (line 257), so it only fires on a successful query. On DB failure, `once.Do` is never called, `br.genesisBlock.ConsensusStart` stays at `genesisConsensusStartUnset` (`-1`), and the guard at line 244 passes for every goroutine on every subsequent request.

**Failed assumption:** The developer assumed `sync.Once` would prevent repeated DB calls. It does not — it only prevents repeated assignments. The DB query itself is unguarded.

**Exploit flow:**
1. Network partition isolates Rosetta from its PostgreSQL backend (or DB is slow/down at startup).
2. Attacker sends N concurrent POST requests to any block-related endpoint (e.g., `/block` with a `FindByHash` call) — no credentials required.
3. Each goroutine reads `ConsensusStart == -1`, passes the guard, calls `GetDbWithContext` (acquiring a pool slot), and executes `selectGenesis`.
4. The query hangs until `statementTimeout` (default 20 seconds per `rosetta/app/db/client.go` line 36, configured at 20s per docs).
5. With `MaxOpenConnections` defaulting to 100 (`rosetta/app/db/db.go` line 33), 100 concurrent attacker requests saturate the pool.
6. All legitimate requests block waiting for a free connection for the full 20-second window, then the attacker repeats.

**Why existing checks fail:**

- The Traefik middleware (`inFlightReq: 5`, `rateLimit: average: 10`) is defined in `charts/hedera-mirror-rosetta/values.yaml` lines 149–166 but is **disabled by default** because `global.middleware: false` (line 95). Deployments not using the Helm chart or not enabling middleware have zero rate limiting.
- Even with middleware enabled, `inFlightReq: 5` per IP is trivially bypassed with 20 source IPs to fill the 100-connection pool.
- `statementTimeout` (20s) limits per-connection hold time but does not prevent pool exhaustion — it only bounds the DoS window per wave of requests.

### Impact Explanation
All five public `blockRepository` methods (`FindByHash`, `FindByIdentifier`, `FindByIndex`, `RetrieveGenesis`, `RetrieveLatest`) call `initGenesisRecordFile` before doing any work. Pool exhaustion blocks all of them simultaneously. During a real network partition — already a degraded state — an attacker can ensure the Rosetta API returns errors or hangs for every legitimate caller for the duration of the attack, completely preventing block data retrieval and any dependent Rosetta operations (balance checks, transaction lookups). Severity: **High** (full API DoS, no authentication required, exploitable during the most critical recovery window).

### Likelihood Explanation
The Rosetta API is a public HTTP service with no authentication. An attacker needs only the ability to send concurrent HTTP POST requests — achievable from a single machine with a basic script. The attack is most effective during a network partition (an already-abnormal condition), but can also be triggered at service startup before genesis is initialized. The attack is repeatable in 20-second waves indefinitely. The default deployment (Helm chart with `global.middleware: false`) has no rate limiting, making this trivially exploitable.

### Recommendation
Move `sync.Once` to wrap the entire initialization including the DB query, preventing concurrent goroutines from all issuing the query simultaneously:

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
    })
    return initErr
}
```

Note: if `once.Do` must be retryable on failure (i.e., allow retry after DB recovers), use a `sync.Mutex` to serialize the initialization attempt instead of `sync.Once`, resetting a flag only on success. Additionally, enable the Traefik rate-limiting middleware by default (`global.middleware: true`) as a defense-in-depth measure.

### Proof of Concept
**Preconditions:** Rosetta API is running; database is unreachable or partitioned (simulate with a firewall rule blocking port 5432, or by starting Rosetta before the DB is available).

**Steps:**
```bash
# 1. Confirm genesis is uninitialized (service just started or DB is down)
# 2. Send 100 concurrent FindByHash requests (any hash value, no auth needed)
for i in $(seq 1 100); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"}}' &
done
wait

# 3. Immediately send a legitimate request — it will block or return a DB error
curl -X POST http://<rosetta-host>:5700/network/status \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'
```

**Expected result:** The 100 attacker goroutines each hold a DB connection for 20 seconds (statementTimeout). The legitimate request at step 3 cannot acquire a connection and either blocks or fails with a database error, demonstrating full pool exhaustion DoS.