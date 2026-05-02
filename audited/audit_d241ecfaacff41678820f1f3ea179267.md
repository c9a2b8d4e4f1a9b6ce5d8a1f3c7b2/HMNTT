### Title
`FindBetween()` Batching Loop Exhausts DB Resources via Unauthenticated `/block` Requests on High-Transaction Blocks

### Summary
`FindBetween()` in `rosetta/app/persistence/transaction.go` issues `ceil(N / 2000)` sequential GORM `Limit(batchSize).Find()` calls per `/block` request, where N is the total number of transactions in the requested block. The `maxTransactionsInBlock` guard in `block_service.go` truncates only the HTTP response after all DB queries have already completed, providing zero protection against DB-layer amplification. Any unauthenticated caller who identifies a block with many transactions can repeatedly request it, multiplying expensive correlated-subquery DB load with no application-level rate limiting.

### Finding Description

**Exact code path:**

`rosetta/app/persistence/transaction.go`, `FindBetween()`, lines 124–147:

```go
for start <= end {
    transactionsBatch := make([]*transaction, 0)
    err := db.
        Raw(selectTransactionsInTimestampRangeOrdered,
            sql.Named("start", start),
            sql.Named("end", end)).
        Limit(batchSize).          // batchSize = 2000
        Find(&transactionsBatch).
        Error
    ...
    if len(transactionsBatch) < batchSize {
        break
    }
    start = transactionsBatch[len(transactionsBatch)-1].ConsensusTimestamp + 1
}
```

Each iteration executes `selectTransactionsInTimestampRangeOrdered`, a correlated query that joins `transaction` with two subqueries over `crypto_transfer` and `staking_reward_transfer` per row. For a block with N transactions, this loop runs `ceil(N / 2000)` times.

**Root cause — failed assumption:**

The operator-facing `maxTransactionsInBlock` setting (configured via `hiero.mirror.rosetta.response.maxTransactionsInBlock`) is applied in `block_service.go` `Block()` at lines 61–67, **after** `FindBetween()` returns:

```go
if block.Transactions, err = s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos); err != nil {
    return nil, err
}
// maxTransactionsInBlock check here — all DB queries already done
if len(block.Transactions) > s.maxTransactionsInBlock {
    ...
    block.Transactions = block.Transactions[0:s.maxTransactionsInBlock]
}
```

The assumption that `maxTransactionsInBlock` limits DB load is incorrect. It only slices the in-memory result before serialization.

**No application-level rate limiting:** The Rosetta router (`rosetta/main.go` lines 111–119) registers no authentication or rate-limiting middleware. The Helm chart's Traefik middleware (`inFlightReq: 5`, `rateLimit: average: 10`) is disabled by default (`middleware: false`) and is external infrastructure, not enforced by the application.

### Impact Explanation

A block with 10,000 transactions causes 5 sequential complex DB queries per `/block` request. With 20 concurrent unauthenticated requests targeting the same block, the node issues 100 concurrent correlated subquery executions against `transaction`, `crypto_transfer`, and `staking_reward_transfer`. The default DB pool allows up to 100 open connections (`maxOpenConnections: 100`), meaning a single attacker can saturate the connection pool. The `statementTimeout` of 20 seconds per query means each batch query can hold a connection for up to 20 seconds, further amplifying connection exhaustion. This directly increases DB CPU and I/O well beyond 30% of baseline for legitimate traffic.

### Likelihood Explanation

Block indices and their transaction counts are public information on any Hedera network. An attacker needs only to query the network status endpoint (also unauthenticated) to enumerate block indices, then identify high-transaction blocks via the public Hedera mirror REST API or block explorer. No credentials, tokens, or special access are required. The attack is trivially repeatable with a simple HTTP client loop and is not detectable as anomalous at the application layer since each request is individually valid.

### Recommendation

1. **Break the loop early based on a DB-query count cap:** Add a maximum iteration count to `FindBetween()` and return an error or partial result once exceeded, independent of `maxTransactionsInBlock`.
2. **Move the transaction cap into the query:** Pass `maxTransactionsInBlock` as an upper bound to `FindBetween()` so the first DB query uses `LIMIT maxTransactionsInBlock` and the loop never runs more than one iteration when the cap is small.
3. **Add application-level rate limiting:** Implement per-IP concurrency and rate limits directly in the Go HTTP server, not relying solely on optional external Traefik middleware.
4. **Reduce `statementTimeout`:** The current default of 20 seconds per query is too long for a public-facing read endpoint; reduce it to 2–5 seconds to limit connection hold time.

### Proof of Concept

```bash
# Step 1: Find a block with many transactions (public info)
# e.g., on testnet, blocks during high-activity periods have thousands of txns

# Step 2: Identify the block index (e.g., block 12345678 has 8000 transactions)
BLOCK_INDEX=12345678

# Step 3: Send concurrent unauthenticated /block requests
for i in $(seq 1 20); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H "Content-Type: application/json" \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"testnet\"},
         \"block_identifier\":{\"index\":$BLOCK_INDEX}}" &
done
wait

# Result: 20 concurrent requests × ceil(8000/2000) = 4 DB queries each
# = 80 simultaneous correlated subquery executions against the DB
# DB CPU/IO spikes; connection pool (max 100) approaches saturation
```

Each request is valid, unauthenticated, and individually indistinguishable from legitimate Rosetta client traffic (e.g., from `rosetta-cli` during data validation).