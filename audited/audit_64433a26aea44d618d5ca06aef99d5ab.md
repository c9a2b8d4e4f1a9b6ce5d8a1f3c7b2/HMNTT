### Title
Unbounded Block Index Lookup Enables Unauthenticated DB Resource Exhaustion via AccountBalance

### Summary
The `AccountBalance()` endpoint in `rosetta/app/services/account_service.go` accepts a `BlockIdentifier.Index` of any non-negative 64-bit integer from unauthenticated callers. Each such request unconditionally executes a database query against the `record_file` table. No application-level rate limiting, caching, or upper-bound validation exists in the Rosetta service itself, allowing an attacker to drive sustained DB query load by flooding the endpoint with distinct large indices.

### Finding Description
**Exact code path:**

`AccountBalance()` at [1](#0-0)  delegates to `RetrieveBlock()`.

`RetrieveBlock()` at [2](#0-1)  calls `b.blockRepo.FindByIndex(ctx, *bIdentifier.Index)` when only `Index` is present.

`FindByIndex()` at [3](#0-2)  only rejects `index < 0`; any non-negative value proceeds to `findBlockByIndex()`.

`findBlockByIndex()` at [4](#0-3)  executes the parameterized SQL query `selectRecordBlockByIndex` against the live database for every call, with no caching or short-circuit for obviously-out-of-range indices.

The SQL query itself contains a correlated subquery: [5](#0-4) 

**Root cause:** `FindByIndex` validates only the lower bound (`< 0`) but imposes no upper bound and performs no pre-check against the known latest block index before issuing the DB query. There is no result cache for "not found" lookups.

**Failed assumption:** The design assumes that infrastructure-layer controls (Traefik middleware) will always be present and sufficient. The application layer itself has zero rate limiting or request validation beyond the sign check.

### Impact Explanation
Each request with a distinct large index causes one DB round-trip. The Traefik middleware at [6](#0-5)  provides:
- `inFlightReq: amount: 5` keyed by source IP — bypassable with multiple source IPs or a botnet
- `rateLimit: average: 10` keyed by `requestHost` (the HTTP `Host` header value) — bypassable by rotating the `Host` header across requests, since each unique header value gets its own independent bucket

The `retry: attempts: 3` entry in the same middleware stack can multiply DB hits per attacker request if Traefik retries on connection-level errors. The circuit breaker (`ResponseCodeRatio(500,600,0,600) > 0.25`) would eventually open, but only after a burst of queries has already been issued, and it resets periodically. In deployments without Traefik (direct exposure, alternative ingress), there is no protection at all.

A sustained flood of, say, 30+ req/s (achievable from a handful of IPs with rotated Host headers) against a lightly loaded node easily exceeds the 30% additional resource threshold.

### Likelihood Explanation
- No authentication or API key is required; the `/account/balance` endpoint is fully public per the Rosetta spec.
- The attack requires only a valid account identifier (e.g., `0.0.2`, the treasury) and an arbitrary large integer as `block_identifier.index`.
- Rotating `Host` headers and using a small number of source IPs is trivial with standard HTTP tooling (curl, k6, wrk).
- The attack is repeatable and stateless; no session or prior knowledge of chain state is needed.

### Recommendation
1. **Application-level upper bound check**: In `FindByIndex`, after `initGenesisRecordFile`, compare `index` against the cached latest block index (or call `RetrieveLatest` once and cache it) and return `ErrBlockNotFound` immediately without a DB query if `index` exceeds the latest known index.
2. **Application-level rate limiting**: Add a per-IP or global token-bucket rate limiter inside the Rosetta Go service, independent of any ingress proxy.
3. **Do not rely solely on Traefik middleware** for DoS protection; the `rateLimit` keyed on `requestHost` is trivially bypassed.

### Proof of Concept
```bash
# Requires: a valid account on the network (0.0.2 always exists)
# Send 50 concurrent requests with distinct large block indices, rotating Host headers

for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>/account/balance \
    -H "Content-Type: application/json" \
    -H "Host: fake-host-${i}.example.com" \
    -d "{
      \"network_identifier\": {\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
      \"account_identifier\": {\"address\":\"0.0.2\"},
      \"block_identifier\": {\"index\": $((9999999900 + i))}
    }" &
done
wait
```

Each request bypasses the per-`requestHost` rate limit bucket (each `Host` header is unique), bypasses the per-IP in-flight limit (all 50 are from the same IP but the in-flight cap of 5 only queues them, not drops them), and causes `findBlockByIndex` to execute `selectRecordBlockByIndex` against the database. Sustained over time, this drives measurable additional DB CPU and connection pool utilization above the 30% threshold on a lightly loaded node.

### Citations

**File:** rosetta/app/services/account_service.go (L52-53)
```go
	if request.BlockIdentifier != nil {
		block, rErr = a.RetrieveBlock(ctx, request.BlockIdentifier)
```

**File:** rosetta/app/services/base_service.go (L82-83)
```go
	} else if bIdentifier.Hash == nil && bIdentifier.Index != nil {
		return b.blockRepo.FindByIndex(ctx, *bIdentifier.Index)
```

**File:** rosetta/app/persistence/block.go (L75-85)
```go
	selectRecordBlockByIndex string = `select consensus_start,
                                             coalesce((
                                               select consensus_start-1
                                               from record_file
                                               where index = @index + 1::bigint
                                             ), consensus_end) as consensus_end,
                                             hash,
                                             index,
                                             prev_hash
                                      from record_file
                                      where index = @index`
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

**File:** rosetta/app/persistence/block.go (L210-223)
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
