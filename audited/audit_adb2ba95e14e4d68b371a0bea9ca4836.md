### Title
Unauthenticated Concurrent `/block` Requests Cause Redundant Full DB Scans and Serialization, Enabling >30% Resource Exhaustion

### Summary
The Rosetta `/block` endpoint in `rosetta/app/services/block_service.go` has no response-level caching. Every concurrent request for the same high-transaction-count block triggers a full, unbatched database scan via `FindBetween`, in-memory transaction construction, and `ToRosetta()` serialization — all repeated independently per request. An unprivileged external attacker can flood this endpoint with concurrent requests for a known dense block, multiplying CPU and memory consumption well above the 30% baseline threshold.

### Finding Description

**Code path:**

`rosetta/app/services/block_service.go` — `Block()` (lines 47–74): [1](#0-0) 

1. Line 56 calls `s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos)` — this fetches **all** transactions in the block's timestamp range from the database, regardless of `maxTransactionsInBlock`.
2. Lines 61–66 truncate the result to `maxTransactionsInBlock` **after** the full DB fetch. The truncation is purely cosmetic for the response; the full scan always runs.
3. Line 69 calls `updateOperationAccountAlias()` which iterates every operation in the (already truncated) transaction list and performs account alias lookups.
4. Line 73 calls `block.ToRosetta()` which serializes the entire block structure.

**DB query layer — `rosetta/app/persistence/transaction.go` `FindBetween()` (lines 112–171):** [2](#0-1) 

- Fetches in batches of `batchSize = 2000` (line 22), looping until all transactions are retrieved. A block with 10 000 transactions requires 5 sequential DB round-trips per request.
- Each DB row includes JSON-aggregated `crypto_transfers` and `staking_reward_payouts` sub-selects (lines 41–55), making each row expensive to produce.
- **No result cache exists at this layer.**

**No response-level cache for the Rosetta service:**

The `blockAPIService` struct (lines 19–24) holds only an `entityCache` for account alias lookups: [3](#0-2) 

This LRU cache is keyed on `int64` entity IDs, not on block responses. There is no equivalent of the REST API's Redis-backed `responseCacheHandler` for the Rosetta Go service.

**No application-level rate limiting or concurrency control:**

`rosetta/main.go` (lines 217–219) applies only `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware`: [4](#0-3) 

None of these limit concurrent requests or deduplicate in-flight work for the same block.

**The Traefik middleware in the Helm chart** (`charts/hedera-mirror-rosetta/values.yaml` lines 152–160) defines `inFlightReq: amount: 5` per IP and `rateLimit: average: 10` per host: [5](#0-4) 

These are **optional Kubernetes deployment configurations** — they are absent in bare-metal or Docker deployments, and an attacker using multiple source IPs (or a botnet) trivially bypasses the per-IP `inFlightReq` limit. The `rateLimit` is keyed on `requestHost` (the server's hostname), not the client IP, making it ineffective against distributed attackers.

**Root cause / failed assumption:** The design assumes that callers will not hammer the same block repeatedly, or that an upstream proxy will absorb the load. Neither assumption is enforced at the application layer.

### Impact Explanation

A block with N transactions causes O(N/2000) DB round-trips, each with expensive JSON aggregation sub-selects, plus O(N) in-memory object construction and serialization — all repeated for every concurrent request. With `maxTransactionsInBlock` defaulting to a large value (or being bypassed because the full scan runs regardless), a single attacker sending 20–50 concurrent POST requests to `/block` for a known dense block can:

- Saturate the DB connection pool (`Pool.MaxOpenConnections` in `rosetta/app/config/types.go` line 80)
- Spike Go heap allocation from repeated large slice construction
- Increase CPU from repeated JSON marshalling via `ToRosetta()`

This easily exceeds the 30% resource increase threshold on a normally-loaded node, and can degrade or deny service to legitimate Rosetta clients (e.g., exchange reconciliation tooling).

### Likelihood Explanation

- **No authentication required.** The Rosetta spec mandates open POST endpoints; any network-reachable client qualifies.
- **Block identifiers are public.** Block numbers and hashes are visible on any block explorer.
- **Dense blocks are predictable.** High-activity periods (token launches, airdrops) produce blocks with thousands of transactions that are well-known.
- **Trivially scriptable.** A single `curl` loop or `ab -c 50` invocation is sufficient.
- **Deployment gap.** Many operators run the Rosetta service directly (Docker Compose, bare metal) without the Traefik Helm chart, leaving zero rate limiting in place.

### Recommendation

1. **Add a response-level cache** (e.g., an in-process LRU or Redis entry) keyed on `(blockIndex, blockHash)` in `Block()`, so concurrent requests for the same block share a single DB fetch and serialization result.
2. **Use singleflight** (`golang.org/x/sync/singleflight`) to coalesce concurrent in-flight requests for the same block key, eliminating redundant DB work without requiring a persistent cache.
3. **Move the `maxTransactionsInBlock` truncation before the DB fetch** (or add a `LIMIT` to the SQL query) so the database does not scan the full block when only a subset is needed.
4. **Enforce application-level concurrency limits** (e.g., a semaphore or `golang.org/x/time/rate` token bucket) independent of the deployment topology, so protection is not contingent on Traefik being present.

### Proof of Concept

```bash
# Identify a high-transaction block (e.g., block 12345678 on mainnet)
BLOCK_NUM=12345678

# Send 50 concurrent POST requests to /block for the same block
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H "Content-Type: application/json" \
    -d "{
      \"network_identifier\": {\"blockchain\": \"Hedera\", \"network\": \"mainnet\"},
      \"block_identifier\": {\"index\": $BLOCK_NUM}
    }" &
done
wait
```

**Expected result:** Each of the 50 goroutines independently executes `FindBetween` (multiple DB round-trips for a dense block), constructs the full transaction list in memory, and serializes it. CPU and memory on the Rosetta node spike proportionally to the number of concurrent requests × transactions-per-block, with no deduplication or caching to absorb the load. Monitoring `hiero_mirror_rosetta_request_inflight` and DB connection pool utilization will confirm the redundant parallel work.

### Citations

**File:** rosetta/app/services/block_service.go (L19-24)
```go
type blockAPIService struct {
	accountRepo interfaces.AccountRepository
	BaseService
	entityCache            *cache.Cache[int64, types.AccountId]
	maxTransactionsInBlock int
}
```

**File:** rosetta/app/services/block_service.go (L47-73)
```go
func (s *blockAPIService) Block(
	ctx context.Context,
	request *rTypes.BlockRequest,
) (*rTypes.BlockResponse, *rTypes.Error) {
	block, err := s.RetrieveBlock(ctx, request.BlockIdentifier)
	if err != nil {
		return nil, err
	}

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

	if err = s.updateOperationAccountAlias(ctx, block.Transactions...); err != nil {
		return nil, err
	}

	return &rTypes.BlockResponse{Block: block.ToRosetta(), OtherTransactions: otherTransactions}, nil
```

**File:** rosetta/app/persistence/transaction.go (L112-147)
```go
func (tr *transactionRepository) FindBetween(ctx context.Context, start, end int64) (
	[]*types.Transaction,
	*rTypes.Error,
) {
	if start > end {
		return nil, hErrors.ErrStartMustNotBeAfterEnd
	}

	db, cancel := tr.dbClient.GetDbWithContext(ctx)
	defer cancel()

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

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
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
