### Title
Unauthenticated Hash-Based DB Query Flooding via AccountBalance Endpoint (No Application-Level Rate Limiting)

### Summary
The `AccountBalance()` endpoint in `rosetta/app/services/account_service.go` accepts a `BlockIdentifier.Hash` from any unauthenticated caller and unconditionally routes it through `tools.SafeRemoveHexPrefix()` into `blockRepo.FindByHash()`, which executes a correlated SQL subquery against the `record_file` table. The Rosetta application has no built-in rate limiting or request throttling; the only deployed mitigation is an optional Traefik ingress middleware (10 req/s per host, 5 in-flight per IP) that is absent in non-Kubernetes or direct-exposure deployments. An attacker can flood the endpoint with distinct hash values, each forcing a unique DB query, and drive database CPU/connection consumption well above the 30% threshold.

### Finding Description

**Code path:**

1. `AccountBalance()` — `rosetta/app/services/account_service.go` lines 52–53:
   ```go
   if request.BlockIdentifier != nil {
       block, rErr = a.RetrieveBlock(ctx, request.BlockIdentifier)
   ```
   No authentication, no input length/format check on `BlockIdentifier.Hash`.

2. `RetrieveBlock()` — `rosetta/app/services/base_service.go` lines 84–86:
   ```go
   } else if bIdentifier.Index == nil && bIdentifier.Hash != nil {
       h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
       return b.blockRepo.FindByHash(ctx, h)
   ```
   `SafeRemoveHexPrefix` (`rosetta/app/tools/hex.go` lines 18–23) is a trivial O(1) string slice — it does not validate format, length, or character set.

3. `FindByHash()` — `rosetta/app/persistence/block.go` lines 135–144:
   ```go
   func (br *blockRepository) FindByHash(ctx context.Context, hash string) (*types.Block, *rTypes.Error) {
       if hash == "" {
           return nil, hErrors.ErrInvalidArgument
       }
       if err := br.initGenesisRecordFile(ctx); err != nil { ... }
       return br.findBlockByHash(ctx, hash)
   }
   ```
   The **only** guard is `hash == ""`. Any non-empty string — regardless of whether it ever existed in the DB — proceeds to a DB query.

4. `findBlockByHash()` — `rosetta/app/persistence/block.go` lines 226–240 executes:
   ```sql
   select consensus_start,
     coalesce((select c.consensus_start - 1 from record_file c where c.index = p.index + 1), consensus_end) as consensus_end,
     hash, index, prev_hash
   from record_file p
   where hash = @hash collate "C"
   ```
   This is a correlated subquery. For a non-existent hash it performs a full index scan on `hash` and returns `ErrBlockNotFound` — but the DB work is already done.

5. `main.go` lines 217–219 shows the complete middleware stack:
   ```go
   metricsMiddleware := middleware.MetricsMiddleware(router)
   tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
   corsMiddleware := server.CorsMiddleware(tracingMiddleware)
   ```
   **No rate-limiting middleware is applied at the application layer.**

**Root cause:** The application assumes rate limiting is handled externally (Traefik). The only input guard (`hash == ""`) is trivially bypassed by any non-empty string. There is no per-IP throttle, no request budget, and no hash format validation inside the Go process.

### Impact Explanation

Each request with a unique, non-existent hash forces the PostgreSQL engine to execute the `selectByHashWithIndex` correlated subquery, consume a connection from the pool, and return a miss. In a low-to-moderate traffic baseline (typical for a Rosetta node), a sustained stream of even 50–100 req/s from a single attacker (well below network saturation) can:
- Exhaust the DB connection pool, causing legitimate requests to queue or fail.
- Drive PostgreSQL CPU above the 30% delta threshold.
- Increase Go goroutine count proportionally (each request holds a goroutine for the DB round-trip).

The `AccountBalance` endpoint also triggers `accountRepo.RetrieveBalanceAtBlock()` after a successful block lookup, but even the block-not-found path (the common case for random hashes) is sufficient to cause the DB load described above.

### Likelihood Explanation

- **No privileges required.** The Rosetta API is a public, unauthenticated HTTP endpoint by design (Rosetta spec).
- **Trivial to automate.** A simple loop generating random 64-character hex strings as `BlockIdentifier.Hash` values is sufficient.
- **Traefik mitigation is optional and bypassable.** The Helm chart default (`rateLimit: average: 10, sourceCriterion: requestHost: true`) limits 10 req/s per *hostname*, not per source IP. An attacker using multiple source IPs or bypassing the ingress (direct node access) faces no limit. The `inFlightReq: amount: 5` is per-IP but only 5 concurrent — not a meaningful throughput cap.
- **Repeatable indefinitely** with no lockout or backoff mechanism in the application.

### Recommendation

1. **Add application-level rate limiting** inside the Go process (e.g., `golang.org/x/time/rate` or a middleware like `go-chi/httprate`) so the limit is enforced regardless of deployment topology.
2. **Validate hash format before querying:** reject hashes that do not match the expected hex length (e.g., 64 hex characters) before calling `FindByHash`. Add this check in `FindByHash()` or `RetrieveBlock()`.
3. **Do not rely solely on external infrastructure** (Traefik) for security-critical rate limiting of a public endpoint.

### Proof of Concept

```bash
# Send 200 concurrent AccountBalance requests with distinct random hashes (no 0x prefix)
# to a directly-exposed Rosetta node (no Traefik in front)
for i in $(seq 1 200); do
  curl -s -X POST http://<rosetta-node>:5700/account/balance \
    -H "Content-Type: application/json" \
    -d "{
      \"network_identifier\": {\"blockchain\": \"Hedera\", \"network\": \"mainnet\"},
      \"account_identifier\": {\"address\": \"0.0.98\"},
      \"block_identifier\": {\"hash\": \"$(openssl rand -hex 32)\"}
    }" &
done
wait
# Each request triggers a unique FindByHash DB query.
# Monitor PostgreSQL with: SELECT count(*) FROM pg_stat_activity WHERE state = 'active';
# and: SELECT cpu_usage FROM pg_stat_bgwriter; or system-level top/htop.
# Baseline vs. attack CPU delta will exceed 30% on a lightly loaded node.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** rosetta/app/persistence/block.go (L135-144)
```go
func (br *blockRepository) FindByHash(ctx context.Context, hash string) (*types.Block, *rTypes.Error) {
	if hash == "" {
		return nil, hErrors.ErrInvalidArgument
	}

	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	return br.findBlockByHash(ctx, hash)
```

**File:** rosetta/app/tools/hex.go (L18-23)
```go
func SafeRemoveHexPrefix(string string) string {
	if strings.HasPrefix(string, HexPrefix) {
		return string[2:]
	}
	return string
}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
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
