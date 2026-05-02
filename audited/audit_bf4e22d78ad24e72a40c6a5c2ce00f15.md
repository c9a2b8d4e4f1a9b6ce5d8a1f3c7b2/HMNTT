### Title
Unbounded Concurrent `/block/transaction` Requests Cause Multiplicative DB Scan Work via Uncached `FindByHashInBlock()` Queries

### Summary
`BlockTransaction()` in `rosetta/app/services/block_service.go` issues two uncached DB queries per request — `FindByIdentifier()` and `FindByHashInBlock()` — with no application-level rate limiting or concurrency control. An unprivileged attacker can flood the endpoint with concurrent requests targeting the same block (identical `consensusStart`/`consensusEnd` range) but varying transaction hashes, causing N×2 simultaneous DB queries that linearly multiply database CPU and I/O consumption. The only rate-limiting controls exist in an optional, conditionally-deployed Traefik middleware that is not enforced at the application layer.

### Finding Description

**Exact code path:**

`BlockTransaction()` at `rosetta/app/services/block_service.go:77-102` unconditionally executes two DB queries per request:

1. `s.FindByIdentifier(ctx, request.BlockIdentifier.Index, h)` → `blockRepository.FindByIdentifier()` at `rosetta/app/persistence/block.go:147-169` — DB query against the `record_file` table.
2. `s.FindByHashInBlock(ctx, request.TransactionIdentifier.Hash, block.ConsensusStartNanos, block.ConsensusEndNanos)` → `transactionRepository.FindByHashInBlock()` at `rosetta/app/persistence/transaction.go:173-208` — executes `selectTransactionsByHashInTimestampRange`:

```sql
SELECT ... FROM transaction t
WHERE consensus_timestamp >= @start AND consensus_timestamp <= @end
AND transaction_hash = @hash
```

This query scans the `transaction` table over the full `[consensusStart, consensusEnd]` timestamp range for every request independently. There is **no result caching** for either query.

**Root cause — failed assumption:**

The code assumes requests arrive at a rate manageable by the DB. There is no semaphore, no per-endpoint concurrency limit, no result cache, and no application-level rate limiter anywhere in the rosetta Go codebase. The middleware stack in `rosetta/main.go:217-219` is only `MetricsMiddleware` → `TracingMiddleware` → `CorsMiddleware` — none of which throttle requests.

**Why existing checks fail:**

The Traefik middleware defined in `charts/hedera-mirror-rosetta/values.yaml:149-166` includes `inFlightReq: amount: 5` (per source IP) and `rateLimit: average: 10` (per `requestHost`). However:

- The middleware is **conditionally created** only when both `global.middleware` AND `middleware` Helm values are truthy, per `charts/hedera-mirror-rosetta/templates/middleware.yaml:3`: `{{ if and .Values.global.middleware .Values.middleware -}}`. Deployments without Traefik or without this flag have zero protection.
- The `retry: attempts: 3` entry in the same middleware chain **amplifies** requests: a single client request that triggers a 5xx under load is retried up to 3 times, tripling DB query count.
- The `inFlightReq` limit of 5 is per IP; an attacker using multiple source IPs (or bypassing Traefik entirely by hitting the Go HTTP server directly on its configured port) faces no limit.
- The `rateLimit: average: 10` applies globally per host, not per IP, and is trivially bypassed from multiple hosts.

### Impact Explanation

Each concurrent `/block/transaction` request for the same block independently executes the `selectTransactionsByHashInTimestampRange` query over the same `[consensusStart, consensusEnd]` window. With N concurrent requests, the DB performs N independent range scans of the `transaction` table over the same interval. For a block with many transactions, this is a non-trivial scan. Combined with the `FindByIdentifier` block lookup, each request costs 2 DB round-trips with no deduplication or coalescing. A sustained flood of concurrent requests directly translates to proportional DB CPU, I/O, and connection pool exhaustion, degrading service for all legitimate users. The 30% resource increase threshold is reachable with a modest number of concurrent connections (e.g., 10–20 concurrent requests against a lightly loaded node).

### Likelihood Explanation

The endpoint is publicly accessible with no authentication. The Rosetta API is a standard blockchain interface; its endpoint paths (`/block/transaction`) are well-known. An attacker needs only a valid block hash and index (obtainable from `/block`) and can supply arbitrary (even non-existent) transaction hashes — `FindByHashInBlock()` will still execute the full DB scan before returning `ErrTransactionNotFound`. No special privileges, credentials, or knowledge of internal state are required. The attack is trivially scriptable with any HTTP client capable of concurrent requests (e.g., `curl`, `ab`, `wrk`).

### Recommendation

1. **Application-level rate limiting**: Add a per-IP or global rate limiter (e.g., `golang.org/x/time/rate`) directly in the Go HTTP handler or as middleware in `rosetta/main.go`, independent of infrastructure configuration.
2. **Concurrency semaphore**: Add a bounded semaphore (e.g., `make(chan struct{}, maxConcurrent)`) in `BlockTransaction()` to cap simultaneous in-flight DB queries.
3. **Block lookup caching**: Cache the result of `FindByIdentifier()` keyed on `(index, hash)` — the block data is immutable once written. This eliminates the first DB query for repeated requests to the same block.
4. **Make Traefik middleware non-optional**: Remove the `global.middleware` conditional gate or enforce a minimum rate-limit configuration at the application level so protection is not deployment-dependent.
5. **Remove `retry` from the middleware chain** or scope it to network errors only, to prevent Traefik from amplifying DB load on server-side errors.

### Proof of Concept

**Preconditions:** Rosetta node running in online mode, reachable at `http://<host>:<port>`. Obtain a valid block index and hash via `POST /block` with an empty `block_identifier`.

**Steps:**

```bash
# 1. Get a valid block identifier
BLOCK=$(curl -s -X POST http://<host>:5700/block \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"testnet"},"block_identifier":{}}')

INDEX=$(echo $BLOCK | jq '.block.block_identifier.index')
HASH=$(echo $BLOCK | jq -r '.block.block_identifier.hash')

# 2. Send 50 concurrent /block/transaction requests for the same block,
#    each with a different (non-existent) transaction hash.
#    Each request triggers 2 DB queries over the same timestamp range.
for i in $(seq 1 50); do
  curl -s -X POST http://<host>:5700/block/transaction \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"testnet\"},
         \"block_identifier\":{\"index\":$INDEX,\"hash\":\"$HASH\"},
         \"transaction_identifier\":{\"hash\":\"$(openssl rand -hex 48)\"}}" &
done
wait
```

**Result:** 50 concurrent `FindByHashInBlock()` DB queries execute simultaneously over the same `[consensusStart, consensusEnd]` range. DB CPU and I/O spike proportionally. Monitor with `pg_stat_activity` or DB metrics to confirm N simultaneous identical-range scans. Repeat in a loop to sustain elevated resource consumption above the 30% threshold.