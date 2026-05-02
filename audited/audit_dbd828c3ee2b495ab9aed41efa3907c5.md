### Title
Missing Minimum Hash Length Validation in `FindByHash` Enables Guaranteed-Miss DB Query Griefing

### Summary
`AccountBalance()` accepts a `BlockIdentifier` containing only a hash field and passes it directly to `blockRepo.FindByHash()`. The only guard in `FindByHash()` is a check for an empty string; any non-empty string — including a single hex character — is forwarded to the database as a literal equality match. Because no real block hash is one character long, the query always misses, and the server returns `ErrBlockNotFound` for every such request. An unauthenticated attacker can repeat this at arbitrary rate to generate sustained, guaranteed-miss database load.

### Finding Description

**Exact code path:**

`AccountBalance()` delegates block resolution to `RetrieveBlock()` whenever `request.BlockIdentifier != nil`: [1](#0-0) 

`RetrieveBlock()` strips the optional `0x` prefix and calls `FindByHash()` when only the hash field is populated: [2](#0-1) 

`FindByHash()` validates only that the string is non-empty: [3](#0-2) 

`findBlockByHash()` then issues a full SQL equality query against the `record_file` table: [4](#0-3) 

The SQL predicate is: [5](#0-4) 

**Root cause:** The only input guard is `hash == ""`. There is no minimum length check, no hex-character validation, and no length-range enforcement. A hash of `"a"` (one character) passes the guard, reaches the database, and always returns `gorm.ErrRecordNotFound`, which is mapped to `ErrBlockNotFound`.

**Failed assumption:** The code assumes that any caller-supplied non-empty string is a plausible block hash worth querying for. Real block hashes stored in `record_file.hash` are long hex strings (48-byte / 96-hex-char for Hedera record files); a 1-char input can never match.

**Why existing checks are insufficient:**

- `FindByHash`: only `hash == ""` → passes for `"a"` [6](#0-5) 
- `FindByIdentifier`: same pattern, only `hash == ""` [7](#0-6) 
- No rate limiting or request throttling middleware was found anywhere in the Rosetta Go service. 
- `initGenesisRecordFile` is cached via `sync.Once`, so it does not add per-request overhead after the first call; every subsequent bad-hash request still issues one DB query. [8](#0-7) 

### Impact Explanation
Each request with a 1-char hash causes one database round-trip that is guaranteed to return no rows. At scale this translates to sustained, predictable DB load with zero useful work performed. Because the Rosetta `/account/balance` endpoint requires no authentication and accepts arbitrary JSON, the attacker needs no credentials, no tokens, and no knowledge of real block hashes. The impact is griefing / resource exhaustion of the database layer with no economic cost to the attacker and no direct financial loss to network participants, consistent with the Medium/griefing severity classification.

### Likelihood Explanation
The exploit requires only an HTTP client and a valid (or even invalid — `ErrInvalidAccount` is returned before the block lookup) account address string. The request body is minimal JSON. The attack is trivially scriptable, requires no privileged access, and is repeatable indefinitely. Any public-facing Rosetta deployment is exposed.

### Recommendation
Add a minimum (and maximum) length check on the hash string before issuing the database query. Real Hedera record-file hashes are 96 hex characters (48 bytes). Reject any hash that does not conform:

```go
func (br *blockRepository) FindByHash(ctx context.Context, hash string) (*types.Block, *rTypes.Error) {
    const expectedHashLen = 96 // 48-byte hash as hex
    if len(hash) == 0 || len(hash) != expectedHashLen || !isHex(hash) {
        return nil, hErrors.ErrInvalidArgument
    }
    // ...
}
```

Apply the same guard in `FindByIdentifier`. Additionally, consider adding a rate-limiting middleware at the HTTP router level for all Rosetta endpoints.

### Proof of Concept

```bash
# 1. Start the Rosetta mirror-node service (online mode)
# 2. Send a request with a 1-character block hash:
curl -s -X POST http://localhost:8082/account/balance \
  -H 'Content-Type: application/json' \
  -d '{
    "network_identifier": {"blockchain":"Hedera","network":"mainnet"},
    "account_identifier": {"address":"0.0.98"},
    "block_identifier": {"hash": "a"}
  }'
# Expected response: {"code":...,"message":"block not found",...}

# 3. Loop at high rate to generate sustained DB load:
while true; do
  curl -s -o /dev/null -X POST http://localhost:8082/account/balance \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "account_identifier":{"address":"0.0.98"},
         "block_identifier":{"hash":"a"}}' &
done
# Each iteration causes one guaranteed-miss SQL query against record_file.
```

### Citations

**File:** rosetta/app/services/account_service.go (L52-53)
```go
	if request.BlockIdentifier != nil {
		block, rErr = a.RetrieveBlock(ctx, request.BlockIdentifier)
```

**File:** rosetta/app/services/base_service.go (L84-86)
```go
	} else if bIdentifier.Index == nil && bIdentifier.Hash != nil {
		h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
		return b.blockRepo.FindByHash(ctx, h)
```

**File:** rosetta/app/persistence/block.go (L34-45)
```go
	selectByHashWithIndex string = `select
                                      consensus_start,
                                      coalesce((
                                        select c.consensus_start - 1
                                        from record_file c
                                        where c.index = p.index + 1
                                      ), consensus_end) as consensus_end,
                                      hash,
                                      index,
                                      prev_hash
                                    from record_file p
                                    where hash = @hash collate "C"`
```

**File:** rosetta/app/persistence/block.go (L135-145)
```go
func (br *blockRepository) FindByHash(ctx context.Context, hash string) (*types.Block, *rTypes.Error) {
	if hash == "" {
		return nil, hErrors.ErrInvalidArgument
	}

	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	return br.findBlockByHash(ctx, hash)
}
```

**File:** rosetta/app/persistence/block.go (L151-153)
```go
	if index < 0 || hash == "" {
		return nil, hErrors.ErrInvalidArgument
	}
```

**File:** rosetta/app/persistence/block.go (L226-233)
```go
func (br *blockRepository) findBlockByHash(ctx context.Context, hash string) (*types.Block, *rTypes.Error) {
	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectByHashWithIndex, sql.Named("hash", hash)).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}
```

**File:** rosetta/app/persistence/block.go (L243-263)
```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
	if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
		return nil
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	var rb recordBlock
	if err := db.Raw(selectGenesis, sql.Named("treasury_entity_id", br.treasuryEntityId.EncodedId)).
		First(&rb).Error; err != nil {
		return handleDatabaseError(err, hErrors.ErrNodeIsStarting)
	}

	br.once.Do(func() {
		br.genesisBlock = rb
	})

	log.Infof("Fetched genesis record file, index - %d", br.genesisBlock.Index)
	return nil
}
```
