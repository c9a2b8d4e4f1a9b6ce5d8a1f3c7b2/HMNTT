### Title
Unauthenticated High-Frequency DB Exhaustion via Nil PartialBlockIdentifier in `/block` Endpoint

### Summary
The `Block()` handler in `rosetta/app/services/block_service.go` accepts a `PartialBlockIdentifier` with both `Hash` and `Index` as `nil`, which unconditionally routes to `blockRepo.RetrieveLatest()` — a raw SQL query with no application-level caching or rate limiting. Any unauthenticated external caller can flood this endpoint with such requests, triggering multiple database queries per request (latest block lookup + full transaction range scan + account alias lookups), exhausting database connection pools and degrading service availability.

### Finding Description

**Code path:**

`Block()` at [1](#0-0)  calls `s.RetrieveBlock(ctx, request.BlockIdentifier)`.

`RetrieveBlock()` at [2](#0-1)  has four branches. When both `bIdentifier.Hash == nil` and `bIdentifier.Index == nil`, it falls through to the `else` branch and calls `b.blockRepo.RetrieveLatest(ctx)` with no guard.

`RetrieveLatest()` at [3](#0-2)  executes a raw SQL query (`selectLatestWithIndex`) — `ORDER BY index DESC LIMIT 1` — against the `record_file` table on every invocation. There is no result cache.

The `selectLatestWithIndex` query is defined at: [4](#0-3) 

After the block is retrieved, `Block()` immediately issues two more DB-hitting calls: [5](#0-4) 
- `FindBetween()` — scans all transactions in the block's consensus time range
- `updateOperationAccountAlias()` — issues per-operation account lookups (partially cached via LRU, but cold on first hit)

**Root cause:** The Rosetta spec permits omitting both `hash` and `index` in a `PartialBlockIdentifier` to mean "latest block." The implementation correctly handles this case but provides no application-level caching, no request deduplication, and no rate limiting for this code path.

**Why existing checks fail:**

The only rate-limiting present is in the optional Traefik Helm chart middleware: [6](#0-5) 

This is insufficient for three reasons:
1. It is **optional** — only applied when `global.middleware` and `middleware` values are set; bare deployments have no protection.
2. The `rateLimit` uses `sourceCriterion: requestHost: true` (limits by destination host, not source IP), so a single attacker is not individually throttled.
3. The `retry: attempts: 3` middleware **amplifies** each failed request up to 3×, worsening DB load under stress.

There is no authentication requirement on the `/block` endpoint. [7](#0-6) 

### Impact Explanation
Each request with a nil-nil `PartialBlockIdentifier` causes at minimum two DB queries (latest block + transaction range scan) and potentially many more (account alias lookups). Under concurrent flood, this exhausts the database connection pool, causes query queue buildup, and degrades or denies service to all users of the mirror node — including legitimate blockchain clients and validators. The `record_file` table grows continuously, making the `ORDER BY index DESC` scan increasingly expensive without a covering index.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and a single valid JSON POST body:
```json
{"network_identifier": {...}, "block_identifier": {}}
```
The endpoint is publicly reachable by design (Rosetta is a public blockchain API). The attack is trivially scriptable, repeatable, and requires no special knowledge beyond the Rosetta API specification. Deployments without Traefik ingress (e.g., direct Kubernetes `NodePort`, local dev, or non-Helm deployments) have zero mitigations.

### Recommendation
1. **Application-level caching for `RetrieveLatest()`**: Cache the result with a short TTL (e.g., 1–2 seconds) since the latest block changes infrequently. The `entityCache` pattern already in `blockAPIService` can be reused.
2. **Application-level rate limiting**: Add a per-IP token-bucket limiter in the Go HTTP middleware layer, independent of ingress configuration.
3. **Make Traefik middleware non-optional**: Change the Helm default so `inFlightReq` and `rateLimit` are always enabled, and switch `rateLimit.sourceCriterion` to `ipStrategy` to limit per source IP.
4. **Remove the `retry` middleware** or scope it only to network errors, not application errors, to prevent amplification.

### Proof of Concept
```bash
# Flood the /block endpoint with nil-nil PartialBlockIdentifier
# No credentials required

TARGET="http://<rosetta-host>/block"
NETWORK='{"blockchain":"Hedera","network":"mainnet"}'

while true; do
  curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "{\"network_identifier\":$NETWORK,\"block_identifier\":{}}" \
    -o /dev/null &
done
```

Each concurrent request triggers `RetrieveLatest()` (raw SQL) + `FindBetween()` (transaction range scan). At sufficient concurrency, the PostgreSQL connection pool is exhausted, subsequent queries queue or fail, and the mirror node returns 500 errors to all clients.

### Citations

**File:** rosetta/app/services/block_service.go (L47-71)
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
```

**File:** rosetta/app/services/base_service.go (L79-89)
```go
	if bIdentifier.Hash != nil && bIdentifier.Index != nil {
		h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
		return b.blockRepo.FindByIdentifier(ctx, *bIdentifier.Index, h)
	} else if bIdentifier.Hash == nil && bIdentifier.Index != nil {
		return b.blockRepo.FindByIndex(ctx, *bIdentifier.Index)
	} else if bIdentifier.Index == nil && bIdentifier.Hash != nil {
		h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
		return b.blockRepo.FindByHash(ctx, h)
	} else {
		return b.blockRepo.RetrieveLatest(ctx)
	}
```

**File:** rosetta/app/persistence/block.go (L24-31)
```go
	selectLatestWithIndex string = `select consensus_start,
                                           consensus_end,
                                           hash,
                                           index,
                                           prev_hash
                                    from record_file
                                    order by index desc
                                    limit 1`
```

**File:** rosetta/app/persistence/block.go (L190-208)
```go
func (br *blockRepository) RetrieveLatest(ctx context.Context) (*types.Block, *rTypes.Error) {
	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectLatestWithIndex).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}

	if rb.Index < br.genesisBlock.Index {
		return nil, hErrors.ErrBlockNotFound
	}

	return rb.ToBlock(br.genesisBlock), nil
}
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
