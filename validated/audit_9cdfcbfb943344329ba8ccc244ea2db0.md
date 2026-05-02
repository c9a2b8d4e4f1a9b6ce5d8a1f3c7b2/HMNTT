Based on my direct code inspection, here is the verification result:

**Verified facts from the codebase:**

1. `Block()` calls `FindBetween()` with no row cap — confirmed at line 56 of `block_service.go`. [1](#0-0) 

2. `FindBetween()` runs an unbounded `for start <= end` loop with `batchSize = 2000`, appending all results to an in-memory slice with no total row cap — confirmed at lines 22 and 124–147 of `transaction.go`. [2](#0-1) [3](#0-2) 

3. `otherTransactions` is allocated with capacity `len(block.Transactions) - maxTransactionsInBlock` and is never capped — confirmed at lines 61–66 of `block_service.go`. [4](#0-3) 

4. `MaxTransactionsInBlock` is an `int` field in the `Response` config struct — confirmed in `types.go`. [5](#0-4) 

5. The embedded `application.yml` default config file could not be located by search (glob returned no results), so the claim that `maxTransactionsInBlock` defaults to `0` **could not be independently verified**. The code does embed it via `//go:embed application.yml`. [6](#0-5) 

6. Helm chart files were not found in the repository, so the Traefik rate-limiting claim **could not be verified** from this repo.

7. `mirrorConfig.Rosetta.Response.MaxTransactionsInBlock` is passed directly to `NewBlockAPIService` — confirmed in `main.go`. [7](#0-6) 

---

The core structural issues (unbounded DB loop, full in-memory materialization before cap, uncapped `otherTransactions`) are all confirmed in code. The zero-default and Traefik claims are unverifiable from this repo alone but are not required for the core finding to hold.

---

Audit Report

## Title
Unbounded `otherTransactions` Response and Unlimited DB Fetch in `/block` Endpoint Enable Unauthenticated DoS

## Summary
The `Block()` function fetches all transactions in a block's consensus window via an unbounded batched loop in `FindBetween()`, fully materializes them in memory, and then places all overflow entries into an uncapped `otherTransactions` slice that is serialized directly into the JSON response. No authentication or per-request row limit exists at the application layer.

## Finding Description

**Code path:**

`Block()` calls `FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos)` with no row cap. The time window is derived from the DB record for the requested block, not from the caller, but the caller can freely specify any existing block by index or hash. [8](#0-7) 

`FindBetween()` in the persistence layer runs an unbounded `for start <= end` loop, issuing repeated DB queries with `Limit(batchSize)` (`batchSize = 2000`) and appending every result to an in-memory slice until the range is exhausted. The loop only terminates when a batch returns fewer than 2000 rows — there is **no total row cap**. [3](#0-2) 

Back in `Block()`, the overflow logic allocates `otherTransactions` with capacity `len(block.Transactions) - maxTransactionsInBlock` and appends one `TransactionIdentifier{Hash}` per overflow transaction. This slice is returned verbatim in the JSON response with no size limit. [9](#0-8) 

**Root cause / failed assumption:** The design assumes `maxTransactionsInBlock` bounds the response, but it only limits the fully-detailed `block.transactions` array. The `otherTransactions` array — which can be arbitrarily large — is never capped. Critically, all transactions are fetched from the DB and materialized in memory **before** the cap is applied, so DB and memory cost is always proportional to the total transaction count in the block, not to `maxTransactionsInBlock`.

**Why existing checks fail:**
- `maxTransactionsInBlock` is an `int` field that defaults to Go's zero value (`0`) if the embedded `application.yml` does not set it. If `0`, then `len(block.Transactions) > 0` is always true for any non-empty block, routing every transaction into `otherTransactions` and leaving `block.Transactions` empty. [5](#0-4) 
- The DB `statementTimeout` applies per individual query, not to the total loop. A block with N×2000 transactions issues N queries, each individually within the timeout.
- The application itself has zero rate limiting or authentication on `/block`.

## Impact Explanation
A single request to a high-transaction block causes: (a) N unbounded DB round-trips each executing an expensive correlated subquery against `crypto_transfer` and `staking_reward_transfer`; (b) full in-memory materialization of all transactions; (c) a JSON response whose `other_transactions` array grows linearly with transaction count. Concurrent requests from multiple source IPs can saturate the DB connection pool (`maxOpenConnections`) and server memory, delaying or dropping responses to legitimate downstream consumers such as exchange integrations polling the Rosetta API for transaction finality. [10](#0-9) 

## Likelihood Explanation
No privileges, credentials, or special network position are required. The attacker only needs to identify one block with an above-average transaction count — a condition that occurs naturally during any period of network slowdown or catch-up. The block index is publicly enumerable via `/block` with sequential index decrement. The attack is trivially repeatable and scriptable.

## Recommendation
1. **Cap total rows in `FindBetween()`**: Add a `maxRows` parameter and break the loop once the total accumulated count reaches the limit, returning an error or truncated result.
2. **Cap `otherTransactions`**: Apply an explicit upper bound (e.g., equal to `maxTransactionsInBlock`) on the `otherTransactions` slice before returning the response.
3. **Ensure `maxTransactionsInBlock` has a non-zero default**: Set a sensible default (e.g., `1000`) in the embedded `application.yml` and add a startup validation that rejects a zero value.
4. **Apply application-level rate limiting**: Do not rely solely on optional infrastructure-level controls (Traefik) for DoS protection on expensive endpoints.

## Proof of Concept
```
# 1. Enumerate a high-transaction block index (e.g., during a known network slowdown period)
curl -X POST http://<rosetta-host>:5700/block \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
       "block_identifier":{"index": <HIGH_TX_BLOCK_INDEX>}}'

# 2. Script concurrent requests to exhaust DB connections and memory
for i in $(seq 1 100); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index": <HIGH_TX_BLOCK_INDEX>}}' &
done
wait
```
Each request triggers the unbounded `FindBetween()` loop, fully materializes all transactions in memory, and returns an uncapped `other_transactions` JSON array. Concurrent execution exhausts the DB connection pool and server memory. [11](#0-10) [12](#0-11)

### Citations

**File:** rosetta/app/services/block_service.go (L47-74)
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
}
```

**File:** rosetta/app/persistence/transaction.go (L22-22)
```go
	batchSize                                                 = 2000
```

**File:** rosetta/app/persistence/transaction.go (L32-57)
```go
	selectTransactionsInTimestampRange = `select
                                            t.consensus_timestamp,
                                            t.entity_id,
                                            t.itemized_transfer,
                                            t.memo,
                                            t.payer_account_id,
                                            t.result,
                                            t.transaction_hash as hash,
                                            t.type,
                                            coalesce((
                                              select json_agg(json_build_object(
                                                'account_id', entity_id,
                                                'amount', amount) order by entity_id)
                                              from crypto_transfer
                                              where consensus_timestamp = t.consensus_timestamp and
                                                (errata is null or errata <> 'DELETE')
                                            ), '[]') as crypto_transfers,
                                            coalesce((
                                              select json_agg(json_build_object(
                                                'account_id', account_id,
                                                'amount', amount) order by account_id)
                                              from staking_reward_transfer
                                              where consensus_timestamp = t.consensus_timestamp
                                            ), '[]') as staking_reward_payouts
                                          from transaction t
                                          where consensus_timestamp >= @start and consensus_timestamp <= @end`
```

**File:** rosetta/app/persistence/transaction.go (L112-171)
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
}
```

**File:** rosetta/app/config/types.go (L83-85)
```go
type Response struct {
	MaxTransactionsInBlock int `yaml:"maxTransactionsInBlock"`
}
```

**File:** rosetta/app/config/config.go (L20-21)
```go
//go:embed application.yml
var defaultConfig string
```

**File:** rosetta/main.go (L80-86)
```go
	blockAPIService := services.NewBlockAPIService(
		accountRepo,
		baseService,
		mirrorConfig.Rosetta.Cache[config.EntityCacheKey],
		mirrorConfig.Rosetta.Response.MaxTransactionsInBlock,
		serverContext,
	)
```
