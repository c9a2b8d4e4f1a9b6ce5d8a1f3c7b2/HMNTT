The code references in the claim are accurate. Here is the verification and audit output:

**Verified facts:**
- `block_service.go:56` calls `FindBetween()` unconditionally; truncation at lines 61–66 happens after all DB work is done. [1](#0-0) 
- `transaction.go:124–147` loops in batches of `batchSize = 2000` with no upper bound on total rows fetched. [2](#0-1) [3](#0-2) 
- `ItemizedTransferSlice.Scan()` calls `json.Unmarshal(bytes, &result)` with no size guard. [4](#0-3) 

---

## Audit Report

## Title
Unbounded `FindBetween()` Fetch and JSON Unmarshal Before `maxTransactionsInBlock` Truncation Enables CPU Amplification via `/block` Endpoint

## Summary
`Block()` in `block_service.go` calls `FindBetween()` to retrieve every transaction in a block before applying the `maxTransactionsInBlock` response cap. `FindBetween()` issues repeated batched DB queries (batch size 2000) until all rows in the timestamp range are fetched, and GORM invokes `ItemizedTransferSlice.Scan()` → `json.Unmarshal()` on the `itemized_transfer` JSONB column for every row. The response cap is applied only after all DB round-trips and all unmarshal operations have completed, meaning server-side work is proportional to block size, not response size. An unauthenticated caller can repeatedly target a large block to sustain elevated CPU and memory pressure.

## Finding Description
**Code path:**

1. `rosetta/app/services/block_service.go` line 56: `FindBetween()` is called unconditionally with no row limit tied to `maxTransactionsInBlock`. The guard at lines 61–66 only slices the already-fully-populated `block.Transactions` slice. [1](#0-0) 

2. `rosetta/app/persistence/transaction.go` lines 124–147: `FindBetween()` loops, issuing `LIMIT 2000` queries until `len(transactionsBatch) < batchSize`, accumulating all rows into `transactions`. There is no early exit when the accumulated count exceeds `maxTransactionsInBlock`. [3](#0-2) 

3. `rosetta/app/persistence/domain/transaction.go` lines 32–42: For every row returned by every batch, GORM calls `ItemizedTransferSlice.Scan()`, which calls `json.Unmarshal(bytes, &result)` with no byte-size guard. [4](#0-3) 

**Root cause:** The design assumes `maxTransactionsInBlock` bounds server-side work. It does not — it only bounds the response payload. There is no `LIMIT` in the DB query tied to `maxTransactionsInBlock`, no early termination in the batch loop, and no cap on the byte size of `itemized_transfer` per row.

## Impact Explanation
Every `/block` request for a block with N transactions causes N calls to `json.Unmarshal()` on JSONB arrays, plus ⌈N/2000⌉ DB round-trips, regardless of `maxTransactionsInBlock`. For a block with 10,000 transactions each carrying a multi-KB `itemized_transfer` payload, a single request can force tens to hundreds of MB of JSON parsing and multiple DB queries. Because the endpoint is unauthenticated and the work is proportional to block content rather than response size, a small number of concurrent requests targeting the same large block can sustain elevated CPU and memory pressure on the server, constituting a realistic denial-of-service amplification.

## Likelihood Explanation
The Rosetta `/block` endpoint requires no credentials. On Hedera mainnet, blocks with hundreds to thousands of transactions exist naturally (token-transfer-heavy blocks, DeFi activity). An attacker needs only to identify such a block by scanning block metadata (trivially done via the public Rosetta `/block` API itself or the mirror node REST API) and issue repeated `POST /block` requests. No special privileges, no on-chain action, and no exploit tooling beyond a standard HTTP client are required. The attack is fully repeatable and stateless.

## Recommendation
1. **Add a query-level LIMIT in `FindBetween()`:** Break out of the batch loop as soon as the accumulated transaction count reaches `maxTransactionsInBlock + 1` (one extra to detect overflow), and pass a `LIMIT` to the DB query accordingly. This eliminates the work/response-size mismatch.
2. **Pass `maxTransactionsInBlock` into `FindBetween()`** (or a repository-level cap) so the persistence layer can enforce it at the DB query level rather than relying on the service layer to truncate after the fact.
3. **Add per-request rate limiting** on the `/block` endpoint as a defense-in-depth measure.

## Proof of Concept
1. Identify a block on Hedera mainnet with a large transaction count (e.g., >2000 transactions) using the mirror node REST API or Rosetta `/block` metadata.
2. Send repeated concurrent `POST /rosetta/block` requests with that block's index/hash:
```json
{
  "network_identifier": { "blockchain": "Hedera", "network": "mainnet" },
  "block_identifier": { "index": <large_block_index> }
}
```
3. Observe server CPU and memory usage. Each request triggers the full `FindBetween()` batch loop and `json.Unmarshal()` for every transaction in the block, while the response is truncated to `maxTransactionsInBlock`. Sustained concurrent requests will cause CPU amplification proportional to block size divided by `maxTransactionsInBlock`.

### Citations

**File:** rosetta/app/services/block_service.go (L56-66)
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
```

**File:** rosetta/app/persistence/transaction.go (L22-22)
```go
	batchSize                                                 = 2000
```

**File:** rosetta/app/persistence/transaction.go (L124-147)
```go
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

**File:** rosetta/app/persistence/domain/transaction.go (L32-42)
```go
func (i *ItemizedTransferSlice) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value", value))
	}

	result := ItemizedTransferSlice{}
	err := json.Unmarshal(bytes, &result)
	*i = result
	return err
}
```
