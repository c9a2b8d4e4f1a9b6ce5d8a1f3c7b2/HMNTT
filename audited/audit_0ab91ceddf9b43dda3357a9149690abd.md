### Title
Unauthenticated DoS via Unbounded Future Block Index Queries Exhausting Database Connection Pool

### Summary
The Rosetta API's `findBlockByIndex` function performs a live database query for any non-negative block index, including arbitrarily large future indices that cannot exist. Because `ErrBlockNotFound` is marked `retriable=true` and the application layer contains zero rate limiting, an unprivileged attacker can flood the service with future-index requests, exhausting the database connection pool and causing `ErrDatabaseError` for legitimate users.

### Finding Description

**Exact code path:**

`rosetta/app/errors/errors.go`, line 60:
```go
ErrBlockNotFound = newError(BlockNotFound, 101, true)  // retriable=true
```

`rosetta/app/persistence/block.go`, `findBlockByIndex()`, lines 210–223:
```go
func (br *blockRepository) findBlockByIndex(ctx context.Context, index int64) (*types.Block, *rTypes.Error) {
    if index < br.genesisBlock.Index {
        return nil, hErrors.ErrBlockNotFound  // early return, no DB hit
    }

    db, cancel := br.dbClient.GetDbWithContext(ctx)
    defer cancel()

    rb := &recordBlock{}
    if err := db.Raw(selectRecordBlockByIndex, sql.Named("index", index)).First(rb).Error; err != nil {
        return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)  // DB query always fires
    }
    ...
}
```

`rosetta/app/persistence/block.go`, `FindByIndex()`, lines 171–181:
```go
func (br *blockRepository) FindByIndex(ctx context.Context, index int64) (*types.Block, *rTypes.Error) {
    if index < 0 {
        return nil, hErrors.ErrInvalidArgument  // only guard: negative index
    }
    if err := br.initGenesisRecordFile(ctx); err != nil {
        return nil, err
    }
    return br.findBlockByIndex(ctx, index)  // any positive index hits DB
}
```

**Root cause:** The only pre-DB guard is `index < 0`. Any positive index — including `9999999999` — passes validation and issues a real SQL query against `record_file`. There is no check against the current chain tip (latest indexed block) before querying.

**Failed assumption:** The design assumes that callers will only request valid, existing block indices. There is no enforcement of this assumption at the API boundary.

**Exploit flow:**
1. Attacker sends POST `/block` with `block_identifier.index = 9999999999` (a future block).
2. `RetrieveBlock` → `blockRepo.FindByIndex` → `findBlockByIndex` → `db.Raw(selectRecordBlockByIndex, ...)` — a real DB query fires.
3. DB returns `gorm.ErrRecordNotFound`; server returns `ErrBlockNotFound` (code 101, `retriable=true`).
4. Attacker repeats in a tight loop from one or more IPs.
5. Each request consumes a DB connection for the duration of the query.
6. Connection pool (`MaxOpenConnections`) is exhausted.
7. Legitimate requests cannot acquire a connection; `handleDatabaseError` returns `ErrDatabaseError` (code 125) to real users.

**Why existing checks fail:**

- **Application-level rate limiting:** A `grep` across all `rosetta/**/*.go` files for `rateLimit`, `throttle`, `inFlightReq` returns **zero matches**. The Go Rosetta service has no built-in rate limiting whatsoever.
- **Traefik middleware** (`charts/hedera-mirror-rosetta/values.yaml`, lines 149–166): The template is conditional — `{{ if and .Values.global.middleware .Values.middleware }}` — meaning it is **not deployed by default** and is absent in non-Kubernetes or misconfigured deployments.
- **Retry amplification:** Even when Traefik is deployed, the `retry: attempts: 3` middleware is configured alongside the rate limiter. Because `ErrBlockNotFound` is `retriable=true`, Traefik retries each failing request up to 3 times, **tripling** the DB query load per client request.
- **`inFlightReq: amount: 5` per IP** is trivially bypassed with multiple source IPs or by staying under the limit while still generating sustained DB load.

### Impact Explanation

Database connection pool exhaustion causes `ErrDatabaseError` (code 125, `retriable=true`) for all concurrent legitimate users — effectively a full denial of service of the Rosetta API. Block queries, transaction queries, and account queries all share the same DB pool. The impact is total service unavailability for the duration of the attack, with no self-healing until the attack stops.

### Likelihood Explanation

No authentication or API key is required to call `/block`. The attack requires only an HTTP client and knowledge of the Rosetta API spec (publicly documented). A single attacker with a modest connection rate (e.g., 100 req/s) can sustain pool exhaustion indefinitely. The `retriable=true` flag on `ErrBlockNotFound` may also cause legitimate Rosetta SDK clients to automatically retry, inadvertently amplifying attacker-induced load. The attack is trivially repeatable and requires no special privileges or insider knowledge.

### Recommendation

1. **Validate index against chain tip before querying:** In `FindByIndex`, call `RetrieveLatest` (or cache the latest index) and reject any `index > latestBlock.Index` with `ErrBlockNotFound` immediately, without issuing a DB query.
2. **Add application-level rate limiting** in the Go Rosetta service (e.g., `golang.org/x/time/rate` per-IP token bucket) independent of infrastructure-layer controls.
3. **Do not rely solely on optional Traefik middleware** for DoS protection; make rate limiting a first-class concern in the application.
4. **Consider changing `ErrBlockNotFound` to `retriable=false`** for index-based lookups, or at minimum document that clients should not retry indefinitely on this error.
5. **Remove or decouple the `retry` Traefik middleware** from endpoints that return `retriable=true` errors for not-found conditions, to prevent retry amplification.

### Proof of Concept

```bash
# No authentication required. Repeat in parallel to exhaust connection pool.
for i in $(seq 1 500); do
  curl -s -X POST http://<rosetta-host>/block \
    -H "Content-Type: application/json" \
    -d '{
      "network_identifier": {"blockchain":"Hedera","network":"mainnet"},
      "block_identifier": {"index": 9999999999}
    }' &
done
wait

# Expected: legitimate /block, /account/balance, etc. requests begin returning:
# {"code":125,"message":"Database error","retriable":true}
```

Each iteration triggers `findBlockByIndex` → `db.Raw(selectRecordBlockByIndex, ...)` → `gorm.ErrRecordNotFound` → `ErrBlockNotFound`. With 500 concurrent requests and a typical `MaxOpenConnections` of 10–20, the pool is exhausted within milliseconds, and all legitimate queries receive `ErrDatabaseError`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rosetta/app/errors/errors.go (L60-60)
```go
	ErrBlockNotFound                     = newError(BlockNotFound, 101, true)
```

**File:** rosetta/app/persistence/block.go (L171-181)
```go
func (br *blockRepository) FindByIndex(ctx context.Context, index int64) (*types.Block, *rTypes.Error) {
	if index < 0 {
		return nil, hErrors.ErrInvalidArgument
	}

	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	return br.findBlockByIndex(ctx, index)
}
```

**File:** rosetta/app/persistence/block.go (L210-224)
```go
func (br *blockRepository) findBlockByIndex(ctx context.Context, index int64) (*types.Block, *rTypes.Error) {
	if index < br.genesisBlock.Index {
		return nil, hErrors.ErrBlockNotFound
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectRecordBlockByIndex, sql.Named("index", index)).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}

	return rb.ToBlock(br.genesisBlock), nil
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

**File:** rosetta/app/config/types.go (L77-81)
```go
type Pool struct {
	MaxIdleConnections int `yaml:"maxIdleConnections"`
	MaxLifetime        int `yaml:"maxLifetime"`
	MaxOpenConnections int `yaml:"maxOpenConnections"`
}
```
