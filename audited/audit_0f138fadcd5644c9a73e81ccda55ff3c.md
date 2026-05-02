### Title
Unbounded In-Memory Accumulation in `FindBetween()` Enables Memory Exhaustion via Concurrent Block Requests

### Summary
`FindBetween()` in `rosetta/app/persistence/transaction.go` accumulates all transaction batches from the database into four simultaneous in-memory data structures (`transactions`, `sameHashMap`, `hashes`, `res`) before returning. The only guard against oversized responses — `maxTransactionsInBlock` — is applied in `block_service.go` **after** `FindBetween()` has already allocated peak memory. An unprivileged user can repeatedly issue concurrent `/block` requests targeting the largest available block, causing multiplicative memory pressure with no rate-limiting or concurrency control visible in the codebase.

### Finding Description
**Code path:**

`rosetta/app/services/block_service.go` `Block()` (line 56) calls `s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos)`. [1](#0-0) 

Inside `FindBetween()` (`rosetta/app/persistence/transaction.go`, lines 123–147), a loop fetches rows in batches of `batchSize = 2000` and appends every batch to a single `transactions` slice with no upper bound on total size: [2](#0-1) [3](#0-2) 

After the loop, three additional structures are built from the fully-loaded slice — `sameHashMap`, `hashes`, and `res` — all coexisting in memory simultaneously: [4](#0-3) 

Only after `FindBetween()` returns does `Block()` apply the `maxTransactionsInBlock` truncation: [5](#0-4) 

**Root cause / failed assumption:** The design assumes that `maxTransactionsInBlock` limits memory, but it is a *response-shaping* guard applied post-allocation. The actual memory peak — all four structures live simultaneously — is never bounded before or during `FindBetween()`.

**Exploit flow:**
1. Attacker (no credentials required) identifies the block index with the highest transaction count by scanning `/block` responses or observing `OtherTransactions` lists.
2. Attacker sends N concurrent `POST /block` requests for that block index.
3. Each goroutine independently executes the full batching loop, building its own copy of all four structures.
4. Peak RSS = N × (size of `transactions` + `sameHashMap` + `hashes` + `res`) for that block.

### Impact Explanation
Each concurrent request independently holds the full in-memory representation of the block. On a busy Hedera mainnet mirror node where a single record file can contain tens of thousands of transactions, a modest fan-out of concurrent requests (e.g., 10–20) can multiply baseline memory consumption well beyond 30%. Sustained or repeated attacks can trigger OOM kills or severe GC pressure, degrading or denying service to all users of the Rosetta API.

### Likelihood Explanation
The `/block` endpoint is unauthenticated and publicly reachable by design (Rosetta API spec). No rate limiting, concurrency semaphore, or per-IP throttle is present in the middleware layer visible in the codebase (`metrics.go`, `trace.go`, `health.go`). The attacker needs only a block index (publicly enumerable) and the ability to issue HTTP requests. The attack is trivially scriptable and repeatable. [6](#0-5) 

### Recommendation
1. **Bound memory before allocation:** Add a configurable hard limit on total transactions fetched inside `FindBetween()`. Break the batching loop and return an error (or truncate) once the accumulated count exceeds `maxTransactionsInBlock`, rather than after the fact.
2. **Move the guard upstream:** Check the transaction count during the batching loop (lines 140–146) and stop accumulating once the limit is reached.
3. **Add concurrency/rate limiting:** Introduce a per-IP or global concurrency semaphore for the `/block` endpoint to cap simultaneous in-flight requests.
4. **Stream instead of accumulate:** Refactor `FindBetween()` to process and emit each batch incrementally rather than appending all batches to a single slice.

### Proof of Concept
```bash
# 1. Find a large block (one with OtherTransactions in the response)
BLOCK_INDEX=<large_block_index>

# 2. Send 20 concurrent /block requests
for i in $(seq 1 20); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H "Content-Type: application/json" \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
         \"block_identifier\":{\"index\":$BLOCK_INDEX}}" &
done
wait

# 3. Observe RSS growth on the rosetta process:
# ps -o pid,rss,vsz -p <rosetta_pid>
# Expected: RSS increases by N × (per-request allocation for that block)
```

Each of the 20 goroutines independently executes the full `FindBetween()` batching loop, holding all four data structures simultaneously, with no guard preventing concurrent accumulation.

### Citations

**File:** rosetta/app/services/block_service.go (L56-67)
```go
	if block.Transactions, err = s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos); err != nil {
		return nil, err
	}

	var otherTransactions []*rTypes.TransactionIdentifier
	if len(block.Transactions) > s.maxTransactionsInBlock {
		otherTransactions = make([]*rTypes.TransactionIdentifier, 0, len(block.Transactions)-s.maxTransactionsInBlock)
		for _, transaction := range block.Transactions[s.maxTransactionsInBlock:] {
			otherTransactions = append(otherTransactions, &rTypes.TransactionIdentifier{Hash: transaction.Hash})
		}
		block.Transactions = block.Transactions[0:s.maxTransactionsInBlock]
	}
```

**File:** rosetta/app/persistence/transaction.go (L22-22)
```go
	batchSize                                                 = 2000
```

**File:** rosetta/app/persistence/transaction.go (L123-147)
```go
	transactions := make([]*transaction, 0)
	for start <= end {
		transactionsBatch := make([]*transaction, 0)
		err := db.
			Raw(
				selectTransactionsInTimestampRangeOrdered,
				sql.Named("start", start),
				sql.Named("end", end),
			).
			Limit(batchSize).
			Find(&transactionsBatch).
			Error
		if err != nil {
			log.Errorf(databaseErrorFormat, hErrors.ErrDatabaseError.Message, err)
			return nil, hErrors.ErrDatabaseError
		}

		transactions = append(transactions, transactionsBatch...)

		if len(transactionsBatch) < batchSize {
			break
		}

		start = transactionsBatch[len(transactionsBatch)-1].ConsensusTimestamp + 1
	}
```

**File:** rosetta/app/persistence/transaction.go (L149-170)
```go
	hashes := make([]string, 0)
	sameHashMap := make(map[string][]*transaction)
	for _, t := range transactions {
		h := t.getHashString()
		if _, ok := sameHashMap[h]; !ok {
			// save the unique hashes in chronological order
			hashes = append(hashes, h)
		}

		sameHashMap[h] = append(sameHashMap[h], t)
	}

	res := make([]*types.Transaction, 0, len(sameHashMap))
	for _, hash := range hashes {
		sameHashTransactions := sameHashMap[hash]
		transaction, err := tr.constructTransaction(sameHashTransactions)
		if err != nil {
			return nil, err
		}
		res = append(res, transaction)
	}
	return res, nil
```

**File:** rosetta/app/middleware/metrics.go (L76-84)
```go
func MetricsMiddleware(next http.Handler) http.Handler {
	return middleware.Instrument{
		Duration:         requestDurationHistogram,
		InflightRequests: requestInflightGauge,
		RequestBodySize:  requestBytesHistogram,
		ResponseBodySize: responseBytesHistogram,
		RouteMatcher:     next.(middleware.RouteMatcher),
	}.Wrap(next)
}
```
