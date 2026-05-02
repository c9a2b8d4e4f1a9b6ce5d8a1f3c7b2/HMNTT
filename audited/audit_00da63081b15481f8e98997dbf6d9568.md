### Title
Pre-Cap Memory Exhaustion in `/block` Endpoint via Unbounded `FindBetween()` Fetch

### Summary
The `Block()` handler in `rosetta/app/services/block_service.go` calls `FindBetween()` which fetches **all** transactions for a block's timestamp range into server memory before the `maxTransactionsInBlock` cap is applied. An unauthenticated attacker who identifies a block with a large number of transactions can send repeated or concurrent `/block` requests, causing the server to allocate unbounded memory per request, leading to denial of service.

### Finding Description

**Code path:**

In `rosetta/app/services/block_service.go` lines 56–66:
```go
if block.Transactions, err = s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos); err != nil {
    return nil, err
}

var otherTransactions []*rTypes.TransactionIdentifier
if len(block.Transactions) > s.maxTransactionsInBlock {
    // truncation happens HERE — after full fetch
    block.Transactions = block.Transactions[0:s.maxTransactionsInBlock]
}
```

`FindBetween()` in `rosetta/app/persistence/transaction.go` lines 123–147 uses a paginated loop with `batchSize = 2000`, but **accumulates all pages into a single in-memory slice** with no upper bound:
```go
transactions := make([]*transaction, 0)
for start <= end {
    transactionsBatch := make([]*transaction, 0)
    // DB query with LIMIT batchSize
    transactions = append(transactions, transactionsBatch...)  // unbounded accumulation
    if len(transactionsBatch) < batchSize {
        break
    }
    start = transactionsBatch[len(transactionsBatch)-1].ConsensusTimestamp + 1
}
```

**Root cause:** The `maxTransactionsInBlock` cap is a post-processing filter applied in the service layer after `FindBetween()` has already materialized the entire transaction list. The repository layer has no knowledge of this cap and applies no limit to total rows fetched. The `batchSize = 2000` only limits individual DB query size, not the total accumulated result set.

**Why existing checks fail:**
- `batchSize = 2000`: Limits per-query DB load only; the loop continues until all transactions in the range are fetched.
- `maxTransactionsInBlock`: Applied at line 61 of `block_service.go`, **after** `FindBetween()` returns the full list.
- DB `statementTimeout = 20s` (config): Applies per individual query, not to the total loop across all batches.
- Traefik rate limiting (`inFlightReq: amount: 5`, `rateLimit: average: 10`): These are **optional** Helm chart middleware, disabled by default (`global.middleware: false` / `middleware: false`). They are not enforced at the application level and are absent in non-Kubernetes deployments.

### Impact Explanation
A block with N transactions causes the server to allocate memory proportional to N before any truncation. Each `transaction` struct includes JSON-encoded `crypto_transfers` and `staking_reward_payouts` fields, making each object potentially several kilobytes. For a block with 50,000 transactions at ~5 KB each, a single request allocates ~250 MB. With multiple concurrent requests targeting the same heavy block, memory pressure multiplies linearly. This can exhaust server memory, causing OOM kills or severe degradation of the Rosetta API service for all users.

### Likelihood Explanation
No authentication or privilege is required to call `/block`. The Rosetta API is a public-facing interface. An attacker only needs to identify a block with a high transaction count (trivially discoverable by querying recent blocks on Hedera mainnet, which regularly processes thousands of transactions per second). The attack is repeatable and requires no special tooling — a simple loop of HTTP POST requests to `/block` with a known high-transaction block index suffices. Without application-level rate limiting, a single attacker can sustain the attack indefinitely.

### Recommendation
Pass `maxTransactionsInBlock` as a query-level `LIMIT` into `FindBetween()` (or add a separate `limit int` parameter to the `TransactionRepository` interface), so the DB query itself caps the number of rows fetched. The current post-fetch truncation should remain as a secondary safeguard but must not be the primary control. Additionally, enforce rate limiting and concurrency limits at the application layer (not solely as optional infrastructure middleware).

### Proof of Concept
1. Identify a block with a large number of transactions (e.g., query `/network/status` for the latest block, then scan recent blocks via `/block` to find one with many transactions, or use a Hedera explorer to find a high-throughput block index).
2. Send concurrent POST requests to the Rosetta `/block` endpoint:
```bash
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H 'Content-Type: application/json' \
    -d '{
      "network_identifier": {"blockchain": "Hedera", "network": "mainnet"},
      "block_identifier": {"index": <HIGH_TX_BLOCK_INDEX>}
    }' &
done
wait
```
3. Monitor server memory (`kubectl top pod` or `ps aux`). Each concurrent request causes `FindBetween()` to load all transactions for that block into memory simultaneously.
4. With sufficient concurrent requests against a sufficiently large block, the process exhausts available memory, resulting in OOM termination or severe latency degradation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** rosetta/app/config/types.go (L83-85)
```go
type Response struct {
	MaxTransactionsInBlock int `yaml:"maxTransactionsInBlock"`
}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L91-96)
```yaml
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
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
