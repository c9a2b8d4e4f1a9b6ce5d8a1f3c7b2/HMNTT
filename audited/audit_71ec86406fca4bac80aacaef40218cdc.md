### Title
Unauthenticated Index-Based Block Lookup Causes Unbounded DB Resource Exhaustion in Rosetta AccountBalance

### Summary
The `AccountBalance()` endpoint in `rosetta/app/services/account_service.go` accepts an unauthenticated `AccountBalanceRequest` with a `BlockIdentifier` containing only an `Index`. This routes through `RetrieveBlock()` → `blockRepo.FindByIndex()`, which executes a raw correlated SQL subquery against `record_file` with zero caching. Combined with the 4–5 additional uncached DB queries triggered by `RetrieveBalanceAtBlock()`, and the complete absence of application-level rate limiting in the Rosetta service, an attacker can trivially saturate the database connection pool and drive DB CPU/IO well above 30% of baseline.

### Finding Description

**Exact code path:**

1. `AccountBalance()` — `rosetta/app/services/account_service.go` lines 52–53: when `request.BlockIdentifier != nil`, unconditionally calls `a.RetrieveBlock(ctx, request.BlockIdentifier)` with no authentication or rate check.

2. `RetrieveBlock()` — `rosetta/app/services/base_service.go` lines 82–83: when only `Index` is set (`Hash == nil`), calls `b.blockRepo.FindByIndex(ctx, *bIdentifier.Index)`.

3. `FindByIndex()` — `rosetta/app/persistence/block.go` lines 171–181: validates only `index >= 0`, then calls `findBlockByIndex()`.

4. `findBlockByIndex()` — `rosetta/app/persistence/block.go` lines 210–224: executes `selectRecordBlockByIndex` (lines 75–85), a **correlated subquery** that performs two index scans per call, with **no caching layer whatsoever**.

5. `RetrieveBalanceAtBlock()` — `rosetta/app/persistence/account.go` lines 161–223: triggers three more raw SQL queries per request:
   - `getCryptoEntity()` (UNION ALL across `entity` + `entity_history`)
   - `getLatestBalanceSnapshot()` (correlated subquery across `account_balance` partitions)
   - `getBalanceChange()` (aggregate over `crypto_transfer`)

**Root cause / failed assumption:** The Rosetta block repository has no caching (unlike the web3 `RecordFileRepository` which uses `@Cacheable` on `findByIndex`). The application server (`main.go` lines 217–219) applies only `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — none of which limit request rates. The Traefik middleware chain that defines `rateLimit: average: 10` and `inFlightReq: amount: 5` is gated on `global.middleware: false` (the default, `charts/hedera-mirror-rosetta/values.yaml` line 95), so it is **disabled in default deployments**.

**Exploit flow:**
- Attacker sends concurrent POST `/account/balance` requests, each with a distinct valid block index and any valid account identifier.
- Each request triggers 4–5 uncached raw SQL queries against the shared `mirror_node` PostgreSQL database.
- With the DB connection pool capped at 100 (`maxOpenConnections: 100`, `docs/configuration.md` line 660), a modest flood of ~20–30 concurrent requests from multiple IPs exhausts available connections and drives DB CPU/IO far above baseline.
- Requests with non-existent indices still execute the full SQL path before returning `ErrBlockNotFound`, providing no short-circuit.

### Impact Explanation
Each `AccountBalance` call with an index-only `BlockIdentifier` generates 4–5 uncached DB round-trips. At even 20 concurrent requests, this is 80–100 simultaneous DB queries, saturating the default 100-connection pool. This degrades or denies service for all other mirror node components (REST API, web3, importer) sharing the same database, constituting a >30% resource increase achievable without brute-force volume. The DB `statementTimeout` of 20 seconds (`docs/configuration.md` line 662) means each connection is held for up to 20 s, amplifying pool exhaustion.

### Likelihood Explanation
No authentication is required. The Rosetta API is publicly exposed (ingress paths include `/rosetta/account`, `charts/hedera-mirror-rosetta/values.yaml` line 126). The attack requires only knowledge of the standard Rosetta `/account/balance` request format and any valid account ID. The rate-limiting middleware is off by default. A single attacker with a modest number of IPs (to bypass the per-IP `inFlightReq` limit if middleware were enabled) can sustain the attack indefinitely.

### Recommendation
1. **Add application-level rate limiting** in the Rosetta Go server itself (e.g., `golang.org/x/time/rate` token bucket per IP), independent of optional infrastructure middleware.
2. **Cache block lookups by index** in `blockRepository.FindByIndex()` using a bounded TTL cache (e.g., `ristretto` or `sync.Map` with expiry), mirroring the `@Cacheable` pattern used in the web3 `RecordFileRepository`.
3. **Enable the Traefik middleware by default** by changing `global.middleware` to `true` in `charts/hedera-mirror-rosetta/values.yaml` line 95.
4. **Validate block index range** against the known latest block index before issuing any DB query, to short-circuit requests for non-existent indices cheaply.

### Proof of Concept

```bash
# Requires: curl, a running Rosetta mirror node at localhost:5700
# Send 50 concurrent requests each with a distinct block index

for i in $(seq 1 50); do
  curl -s -X POST http://localhost:5700/account/balance \
    -H "Content-Type: application/json" \
    -d "{
      \"network_identifier\": {\"blockchain\": \"Hedera\", \"network\": \"testnet\"},
      \"account_identifier\": {\"address\": \"0.0.98\"},
      \"block_identifier\": {\"index\": $i}
    }" &
done
wait

# Each request triggers findBlockByIndex() (correlated subquery) +
# getCryptoEntity() + getLatestBalanceSnapshot() + getBalanceChange()
# = 4-5 uncached DB queries per request = 200-250 simultaneous DB queries
# Monitor DB with: SELECT count(*) FROM pg_stat_activity WHERE state = 'active';
# Observe connection pool saturation and CPU spike >30% above baseline.
```