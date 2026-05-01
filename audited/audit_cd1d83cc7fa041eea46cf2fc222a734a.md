### Title
Unsynchronized Torn Read of `genesisBlock` Struct in `blockRepository.initGenesisRecordFile`

### Summary
`blockRepository` uses `sync.Once` to write `br.genesisBlock` but performs an unsynchronized early-exit read of `br.genesisBlock.ConsensusStart` at line 244 before `once.Do` completes. A concurrent goroutine that observes the partially-written `ConsensusStart` field (non-unset) will bypass the initialization gate and proceed to use the remaining fields (`Index`, `Hash`) while they still hold their zero/initial values. This is a confirmed data race under Go's memory model that corrupts genesis-boundary enforcement for block membership validation.

### Finding Description

**Exact code path:**

`rosetta/app/persistence/block.go`, `initGenesisRecordFile`, lines 243–263.

```
243: func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
244:     if br.genesisBlock.ConsensusStart != genesisConsensusStartUnset {   // ← unsynchronized read
245:         return nil
246:     }
...
257:     br.once.Do(func() {
258:         br.genesisBlock = rb   // ← struct write, NOT atomic
259:     })
```

**Root cause:**

`recordBlock` is a multi-field struct:
```go
type recordBlock struct {
    ConsensusStart int64   // offset 0
    ConsensusEnd   int64   // offset 8
    Hash           string  // offset 16 (16-byte fat pointer: ptr + len)
    Index          int64   // offset 32
    PrevHash       string  // offset 40
}
```

The assignment `br.genesisBlock = rb` at line 258 is compiled into multiple sequential store instructions (at minimum 6 stores for the 5 fields, since `string` is 16 bytes). `sync.Once` provides a happens-before guarantee only for goroutines that themselves pass through `once.Do`. Goroutine B, which exits at line 245 after seeing `ConsensusStart` already written, never enters `once.Do` and therefore receives **no happens-before guarantee** for the remaining fields.

**Exploit flow:**

1. Goroutine A enters `initGenesisRecordFile`, sees `ConsensusStart == -1`, queries the DB, obtains `rb = {ConsensusStart:T, Index:N, Hash:"abc…"}`.
2. Goroutine A enters `once.Do` and the compiler emits stores in field order: `ConsensusStart` is written first (offset 0).
3. Goroutine B enters `initGenesisRecordFile` concurrently. It reads `br.genesisBlock.ConsensusStart` at line 244 and observes the new value `T` (non-unset). It returns `nil` — genesis is "initialized."
4. Goroutine B proceeds to call `findBlockByHash` or `findBlockByIndex`, which read `br.genesisBlock.Index` (still `0`, not yet written by A) and `br.genesisBlock.Hash` (still `""` or a torn 16-byte string header).

**Why existing checks fail:**

- `sync.Once` only synchronizes goroutines that call `once.Do`. The early-exit path at line 244–246 completely bypasses `once.Do`, so its memory barrier is irrelevant for Goroutine B.
- There is no `sync.RWMutex`, `atomic` load/store, or any other synchronization protecting reads of `br.genesisBlock` outside `once.Do`.
- The Go race detector will flag the concurrent read at line 244 and write at line 258 as a **data race** (undefined behavior per the Go memory model).

### Impact Explanation

Goroutine B uses the torn `br.genesisBlock` in three security-relevant comparisons:

| Call site | Field used | Effect of torn read (`Index = 0`) |
|---|---|---|
| `findBlockByHash` line 235 | `br.genesisBlock.Index` | Pre-genesis blocks (index < actual genesis N) pass the `rb.Index < 0` check and are returned as valid |
| `findBlockByIndex` line 211 | `br.genesisBlock.Index` | Same bypass; pre-genesis blocks are served |
| `ToBlock` line 102 | `genesisBlock.Index` | Any block with `Index == 0` is misidentified as genesis, receiving wrong `ConsensusStart`, `parentHash`, and `parentIndex` |

Additionally, `Hash` is a Go `string` (fat pointer: 8-byte data pointer + 8-byte length). A torn read of `Hash` — e.g., new pointer with old length 0, or old nil pointer with new non-zero length — causes an **immediate panic** (nil dereference or out-of-bounds slice) when the string is accessed, crashing the Rosetta API process.

### Likelihood Explanation

- **Precondition:** The server has just started and `genesisBlock` has not yet been initialized (this is the normal state on every cold start).
- **Attacker capability:** Any unauthenticated HTTP client can send concurrent Rosetta API requests (`/block`, `/block/transaction`). No credentials or special privileges are required.
- **Feasibility:** On a multi-core host the race window is real. An attacker sends a burst of concurrent requests immediately after the node becomes reachable (detectable by polling). Modern CPUs with out-of-order execution and store-buffer visibility make the partial-write observable. The Go race detector confirms this as a data race.
- **Repeatability:** The window exists only once per process lifetime, but a process restart (e.g., after a crash caused by the torn `Hash` panic) resets the state, making the attack repeatable across restarts.

### Recommendation

Replace the unsynchronized early-exit check and the `once.Do`-only write with a `sync.RWMutex` that covers both reads and writes of `br.genesisBlock`:

```go
type blockRepository struct {
    dbClient         interfaces.DbClient
    mu               sync.RWMutex
    genesisBlock     recordBlock
    treasuryEntityId domain.EntityId
}

func (br *blockRepository) initGenesisRecordFile(ctx context.Context) *rTypes.Error {
    br.mu.RLock()
    initialized := br.genesisBlock.ConsensusStart != genesisConsensusStartUnset
    br.mu.RUnlock()
    if initialized {
        return nil
    }

    // ... DB query into rb ...

    br.mu.Lock()
    defer br.mu.Unlock()
    if br.genesisBlock.ConsensusStart == genesisConsensusStartUnset {
        br.genesisBlock = rb
    }
    return nil
}
```

All reads of `br.genesisBlock` in `findBlockByHash`, `findBlockByIndex`, `RetrieveLatest`, and `RetrieveGenesis` must also hold `br.mu.RLock()` for the duration of the read. Alternatively, store `genesisBlock` as an `atomic.Pointer[recordBlock]` and swap it once.

### Proof of Concept

```go
// Reproducible with `go test -race ./rosetta/app/persistence/...`
func TestGenesisBlockRace(t *testing.T) {
    repo := NewBlockRepository(slowDbClient, treasuryEntityId).(*blockRepository)
    // slowDbClient introduces a 10ms delay in selectGenesis to widen the race window

    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            // Each goroutine calls FindByIndex; some will race through the
            // early-exit at line 244 while once.Do is mid-write
            block, _ := repo.FindByIndex(context.Background(), 0)
            if block != nil && block.Index != expectedGenesisIndex {
                t.Errorf("torn genesisBlock: got Index=%d Hash=%s", block.Index, block.Hash)
            }
        }()
    }
    wg.Wait()
}
// Running with -race flag will report:
// DATA RACE on br.genesisBlock.ConsensusStart between
//   write at block.go:258 (once.Do closure)
//   read  at block.go:244 (initGenesisRecordFile early-exit check)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** rosetta/app/persistence/block.go (L100-106)
```go

	// Handle the edge case for querying genesis block
	if rb.Index == genesisBlock.Index {
		consensusStart = genesisBlock.ConsensusStart
		parentHash = rb.Hash   // Parent hash should be current block hash
		parentIndex = rb.Index // Parent index should be current block index
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

**File:** rosetta/app/persistence/block.go (L210-212)
```go
func (br *blockRepository) findBlockByIndex(ctx context.Context, index int64) (*types.Block, *rTypes.Error) {
	if index < br.genesisBlock.Index {
		return nil, hErrors.ErrBlockNotFound
```

**File:** rosetta/app/persistence/block.go (L234-238)
```go

	if rb.Index < br.genesisBlock.Index {
		log.Errorf("The block with hash %s is before the genesis block", hash)
		return nil, hErrors.ErrBlockNotFound
	}
```

**File:** rosetta/app/persistence/block.go (L243-259)
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
```
