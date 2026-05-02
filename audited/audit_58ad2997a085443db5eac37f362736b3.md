### Title
Unauthenticated /network/status Endpoint Triggers Uncached DB Queries with No Application-Level Rate Limiting, Enabling DB Connection Pool Exhaustion

### Summary
The `NetworkStatus()` handler in `rosetta/app/services/network_service.go` issues 2–3 sequential database queries on every request with no application-level rate limiting. The only mitigations are optional Traefik infrastructure middleware that uses a per-host (global) rate limit rather than per-IP, and a retry middleware that amplifies load by up to 3×. A distributed attacker can exhaust the 100-connection default pool, denying service to all other users.

### Finding Description
**Exact code path:**

`NetworkStatus()` at `rosetta/app/services/network_service.go` lines 59–88 executes three calls sequentially:

1. `n.RetrieveGenesis(ctx)` → `blockRepository.RetrieveGenesis()` → `initGenesisRecordFile()`. This uses `sync.Once` (`rosetta/app/persistence/block.go` lines 243–263), so after the first successful call the genesis block is cached in memory and **no DB query is issued**. On the very first request (or if genesis is not yet initialized), one DB query runs.

2. `n.RetrieveLatest(ctx)` → `blockRepository.RetrieveLatest()` (`rosetta/app/persistence/block.go` lines 190–208) — **always** executes `selectLatestWithIndex` against the DB, no caching.

3. `n.addressBookEntryRepo.Entries(ctx)` → `addressBookEntryRepository.Entries()` (`rosetta/app/persistence/address_book_entry.go` lines 57–83) — **always** executes 1–2 queries (tries address book file 101, falls back to 102), no caching.

**Result:** Every request after genesis initialization issues 2–3 live DB queries, each acquiring a connection from the GORM pool.

**Application-level rate limiting:** The `main.go` middleware stack (`rosetta/main.go` lines 217–219) is only `MetricsMiddleware → TracingMiddleware → CorsMiddleware`. There is no rate-limiting, concurrency-limiting, or circuit-breaking middleware in the application itself.

**Infrastructure mitigations and their weaknesses** (`charts/hedera-mirror-rosetta/values.yaml` lines 149–166):
- `inFlightReq: amount: 5` per IP — limits one IP to 5 concurrent requests, but does not protect against distributed (multi-IP) attacks.
- `rateLimit: average: 10` with `sourceCriterion: requestHost: true` — this is a **global** rate limit of 10 req/s shared by all clients hitting the same hostname, not a per-IP limit. A single attacker consumes the entire budget.
- `retry: attempts: 3, initialInterval: 100ms` — each client request can produce up to 3 backend requests, **tripling** effective DB load.
- These middlewares are Traefik/Kubernetes Helm chart defaults and are **absent in non-Kubernetes deployments** (bare-metal, Docker Compose, etc.).

**DB connection pool:** Default `maxOpenConnections: 100` (`docs/configuration.md` line 658, `rosetta/app/db/db.go` line 33). With 20 IPs each holding 5 concurrent in-flight requests (each consuming 1 DB connection at a time for sequential queries), and the retry multiplier, the pool can be saturated. Once exhausted, GORM queues new requests; with the default `statementTimeout: 20s`, queued requests hold goroutines and memory, compounding the DoS.

### Impact Explanation
When the DB connection pool is exhausted, all endpoints that require DB access (`/block`, `/account/balance`, `/construction/metadata`, etc.) fail or queue indefinitely. The Rosetta API becomes unavailable to all legitimate users — including exchange integrations and blockchain indexers that depend on it for transaction construction and block data. The impact is a complete denial of service for the online-mode Rosetta API.

### Likelihood Explanation
The endpoint requires no authentication, no API key, and no session. Any internet-accessible deployment is reachable. A single attacker with ~20 IPs (trivially obtained via cloud VMs, proxies, or a small botnet) can bypass the per-IP in-flight limit. In non-Kubernetes deployments (direct Docker, bare-metal), there is zero rate limiting. The attack is trivially scriptable with `curl` or `ab` (Apache Bench) and is continuously repeatable.

### Recommendation
1. **Add application-level concurrency limiting**: Use a semaphore or middleware (e.g., `golang.org/x/net/netutil` or a custom `http.Handler` wrapper) to cap total in-flight `/network/status` requests regardless of deployment environment.
2. **Cache `RetrieveLatest` and `Entries` results**: Add a short TTL cache (e.g., 1–5 seconds) for `RetrieveLatest` and `Entries` results, similar to the existing `sync.Once` pattern for genesis. This reduces DB queries per request to near-zero under load.
3. **Fix the rate limit criterion**: Change `sourceCriterion: requestHost: true` to `sourceCriterion: ipStrategy: depth: 1` so the rate limit is per-IP, not global.
4. **Remove or scope the retry middleware**: The `retry: attempts: 3` middleware should not apply to read endpoints that are already failing due to overload; it amplifies the attack.
5. **Ensure middleware is enforced**: Make rate limiting a mandatory application-layer concern, not solely an infrastructure concern.

### Proof of Concept
**Preconditions:** Rosetta API running in online mode, accessible over the network (with or without Traefik).

**Steps:**
```bash
# From 20 different IPs (or using a tool that spoofs/rotates source IPs):
# Each IP runs:
for i in $(seq 1 5); do
  curl -s -X POST http://<rosetta-host>:5700/network/status \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
done

# Repeat from 20 IPs simultaneously.
# With 20 IPs × 5 concurrent = 100 concurrent requests,
# each holding 1–2 DB connections for ~20–200ms per query,
# the pool of 100 connections is saturated.
```

**Expected result:** Subsequent requests to any DB-backed endpoint return errors or time out. The `/health/readiness` endpoint (which itself calls `/network/status`) also fails, causing Kubernetes to mark pods as not ready and potentially triggering cascading restarts.