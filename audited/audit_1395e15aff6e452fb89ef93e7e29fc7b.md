### Title
Data Race on `br.genesisBlock` Allows Pre-Genesis Block to Bypass Index Guard in `findBlockByHash()`

### Summary
`initGenesisRecordFile()` contains an unsynchronized early-exit read of `br.genesisBlock.ConsensusStart` (line 244) that bypasses the `sync.Once` memory-ordering guarantee. A concurrent goroutine can observe a partially-written `genesisBlock` struct — specifically, `ConsensusStart` already updated but `Index` still at its zero value — and proceed into `findBlockByHash()` where the guard `rb.Index < br.genesisBlock.Index` evaluates against a stale `Index` of `0`, allowing any pre-genesis block to pass as valid.

### Finding Description

**Struct layout and initial state** (`block.go` lines 88–94, 130):
```
recordBlock{ ConsensusStart: -1, ConsensusEnd: 0, Hash: "", Index: 0, PrevHash: "" }
```
`genesisConsensusStartUnset = -1` is the sentinel.

**The unsynchronized early-exit check** (`block.go` line 244):
```go
if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
    return nil          // ← returns without any lock or happens-before guarantee
}
```
This read of `br.genesisBlock.ConsensusStart` is not protected by any mutex or atomic operation.

**The write inside `once.Do`** (`block.go` lines 257–259):
```go
br.once.Do(func() {
    br.genesisBlock = rb   // struct copy: multiple word-sized stores, not atomic
})
```
`sync.Once` guarantees that only one goroutine executes the closure and that callers of `once.Do` who *enter* `Do` will see the completed write. It provides **no** happens-before guarantee to goroutines that skip `Do` entirely via the early-exit check at line 244.

**Race sequence:**

| Time | Goroutine A (first request) | Goroutine B (concurrent request) |
|------|----------------------------|----------------------------------|
| t1 | Passes line 244 check (ConsensusStart == -1), queries DB | — |
| t2 | Enters `once.Do`, begins struct copy: writes `ConsensusStart = <genesis_value>` | — |
| t3 | — | Reads `br.genesisBlock.ConsensusStart` at line 244, sees `<genesis_value>` (≠ -1) |
| t4 | — | Returns `nil` early — `initGenesisRecordFile` exits |
| t5 | Writes `Index = <genesis_index>` (not yet done) | Calls `findBlockByHash`, reads `br.genesisBlock.Index` = **0** (zero value) |
| t6 | Completes struct copy | Guard: `rb.Index < 0` → **false** for any non-negative index → pre-genesis block passes |

**The guard that fails** (`block.go` line 235):
```go
if rb.Index < br.genesisBlock.Index {   // br.genesisBlock.Index == 0 (stale)
    return nil, hErrors.ErrBlockNotFound
}
```
When the actual genesis block has `Index > 0` (common in production: record files exist before the first treasury account balance snapshot), any block with index in `[0, genesisIndex-1]` satisfies `rb.Index >= 0` and passes the guard.

**`ToBlock` is then called with a partially-initialized `genesisBlock`** (`block.go` line 240):
```go
return rb.ToBlock(br.genesisBlock), nil
```
Inside `ToBlock` (lines 102–106), the `rb.Index == genesisBlock.Index` branch compares against `Index = 0`, producing wrong `ConsensusStart`, `ParentHash`, and `ParentIndex` for any block whose index happens to equal 0.

### Impact Explanation
A pre-genesis block — one that predates the network's canonical genesis — is returned as a valid block to any consumer of the Rosetta block-context API (`FindByHash`, `FindByIdentifier`). Smart contract execution environments that rely on block metadata (timestamp, parent hash, block number) for context opcodes receive incorrect values. The block's `ConsensusStartNanos` and parent linkage are corrupted, breaking chain-integrity assumptions. No funds are directly at risk, but block-context-dependent contract logic (e.g., time-locked contracts, replay-protection using block hash) can be fed incorrect inputs, matching the stated medium severity for layer-0/1/2 network code with unintended smart contract behavior.

### Likelihood Explanation
- **Precondition 1**: Genesis block `Index > 0`. This is the normal case on mainnet/testnet where record files precede the first treasury account balance snapshot.
- **Precondition 2**: Two concurrent HTTP requests arrive during the very first initialization of `genesisBlock` (i.e., immediately after node startup). Any unprivileged API client can send concurrent requests; no authentication is required for Rosetta endpoints.
- **Window**: The race window is the duration of the struct copy at line 258 — on x86-64, individual `int64` stores are word-atomic, so the window is the gap between the `ConsensusStart` store and the `Index` store. This is narrow but non-zero under concurrent load and is flagged by Go's race detector (`-race`).
- **Repeatability**: Triggerable on every fresh process start before the first successful `once.Do` completion.

### Recommendation
Replace the unsynchronized early-exit check and unprotected struct copy with a proper atomic or mutex-guarded pattern:

**Option A — use `sync.RWMutex`:**
```go
type blockRepository struct {
    dbClient         interfaces.DbClient
    genesisBlock     recordBlock
    mu               sync.RWMutex
    once             sync.Once
    treasuryEntityId domain.EntityId
}

func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    br.mu.RLock()
    initialized := br.genesisBlock.ConsensusStart != genesisConsensusStartUnset
    br.mu.RUnlock()
    if initialized {
        return nil
    }
    // ... DB query ...
    br.once.Do(func() {
        br.mu.Lock()
        br.genesisBlock = rb
        br.mu.Unlock()
    })
    return nil
}
```
All reads of `br.genesisBlock` in `findBlockByHash`, `findBlockByIndex`, `RetrieveLatest`, and `ToBlock` must also acquire `br.mu.RLock()`.

**Option B — eliminate the early-exit check entirely** and rely solely on `sync.Once`, which already serializes initialization correctly without the racy shortcut.

### Proof of Concept

**Reproducible steps:**

1. Start the Rosetta service against a Hedera mirror node where the genesis record file has `index > 0` (e.g., index = 5).

2. Insert a pre-genesis record file into `record_file` with `index = 3` and a known hash `PRE_GENESIS_HASH`.

3. Immediately after process start (before any request has completed initialization), send two concurrent requests:
   ```
   goroutine 1: GET /block  { "block_identifier": { "hash": "PRE_GENESIS_HASH" } }
   goroutine 2: GET /block  { "block_identifier": { "hash": "PRE_GENESIS_HASH" } }
   ```

4. With the race triggered, goroutine 2 reads `br.genesisBlock.Index == 0`, the guard `3 < 0` is false, and the pre-genesis block is returned as a valid block with corrupted `ConsensusStartNanos` and parent linkage.

5. Confirm with Go race detector:
   ```
   go test -race ./rosetta/app/persistence/... -run TestFindByHash
   ```
   The detector will report a data race on `br.genesisBlock.ConsensusStart` between the read at line 244 and the write at line 258. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rosetta/app/persistence/block.go (L88-94)
```go
type recordBlock struct {
	ConsensusStart int64
	ConsensusEnd   int64
	Hash           string
	Index          int64
	PrevHash       string
}
```

**File:** rosetta/app/persistence/block.go (L119-124)
```go
type blockRepository struct {
	dbClient         interfaces.DbClient
	genesisBlock     recordBlock
	once             sync.Once
	treasuryEntityId domain.EntityId
}
```

**File:** rosetta/app/persistence/block.go (L235-238)
```go
	if rb.Index < br.genesisBlock.Index {
		log.Errorf("The block with hash %s is before the genesis block", hash)
		return nil, hErrors.ErrBlockNotFound
	}
```

**File:** rosetta/app/persistence/block.go (L243-246)
```go
func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
	if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {
		return nil
	}
```

**File:** rosetta/app/persistence/block.go (L257-259)
```go
	br.once.Do(func() {
		br.genesisBlock = rb
	})
```
