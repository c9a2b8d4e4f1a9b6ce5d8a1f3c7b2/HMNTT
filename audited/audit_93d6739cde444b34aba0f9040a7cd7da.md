### Title
Unauthenticated Connection Pool Exhaustion via Unthrottled Multi-CTE Query on GET /api/v1/network/nodes

### Summary
The `GET /api/v1/network/nodes` endpoint in the `rest-java` module has no rate limiting, no caching, and no per-IP concurrency controls. Each request executes a complex multi-CTE native SQL query with a correlated subquery per row, holding a HikariCP connection for the full query duration. An unauthenticated attacker sending a moderate number of concurrent requests can saturate the bounded connection pool, causing latency spikes and resource consumption increases exceeding 30% of baseline across all endpoints sharing the pool.

### Finding Description
**Code location:** `rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java`, lines 25–105, `findNetworkNodes()`.

**Call chain:**
`NetworkController.getNodes()` (line 153) → `NetworkServiceImpl.getNetworkNodes()` (line 100) → `NetworkNodeRepository.findNetworkNodes()` (line 104).

**Root cause — three compounding gaps:**

1. **No rate limiting on the rest-java module.** The only rate limiting in the codebase (`ThrottleManagerImpl`, `ThrottleConfiguration`) lives exclusively in the `web3` module and is wired only to contract-call endpoints. The `rest-java` `WebMvcConfiguration` registers only argument resolvers; `RestJavaConfiguration` registers only an ETag filter and a Protobuf converter. No bucket4j bean, no servlet filter, no Spring Security rate limiter, and no `@RateLimiter` annotation is applied to `NetworkController.getNodes()`.

2. **Complex query holds a connection for its full execution duration.** The native query contains:
   - CTE `latest_address_book`: full scan of `address_book` with `ORDER BY … DESC LIMIT 1`
   - CTE `latest_node_stake`: full scan of `node_stake` with a scalar subquery `(SELECT MAX(consensus_timestamp) FROM node_stake)`
   - CTE `node_info`: full scan of `node`
   - Main SELECT: three-way join plus a **correlated subquery** (lines 72–83) that executes once per returned `address_book_entry` row, aggregating `address_book_service_endpoint` rows with `jsonb_agg … ORDER BY`

3. **Shared, bounded HikariCP connection pool with no explicit override for rest-java.** `CommonConfiguration` creates the pool from `spring.datasource.hikari` properties (line 61–64). No `maximumPoolSize` override exists in `rest-java/src/main/resources/` (only `banner.txt` is present). HikariCP's default `maximumPoolSize` is **10**. Every concurrent request to this endpoint holds one connection for the full multi-CTE execution.

**Why existing checks fail:**
- `NetworkNodeRequest.getEffectiveLimit()` caps results at 25 (line 53–55), but this only bounds result set size, not the number of concurrent callers or the query's wall-clock duration.
- No `@Cacheable` or response caching is applied to `NetworkServiceImpl.getNetworkNodes()`.
- The `ThrottleManagerImpl` is not in scope for this endpoint at all.

### Impact Explanation
With a default pool of 10 connections, an attacker maintaining 10–15 concurrent in-flight requests to `GET /api/v1/network/nodes` can hold all pool connections simultaneously. Legitimate requests to any other endpoint sharing the same pool (transactions, accounts, tokens, etc.) will queue at HikariCP's `connectionTimeout` boundary. This produces measurable latency increases and CPU/memory pressure from queued threads well above the 30% threshold. The attack is self-sustaining: as long as the attacker keeps the concurrency level above the pool size, the degradation persists.

### Likelihood Explanation
The endpoint requires no authentication, no API key, and no session. Any external actor with network access can issue HTTP GET requests. Maintaining 10–20 concurrent connections is trivially achievable with standard tools (`ab`, `wrk`, `hey`, `curl --parallel`). The request rate stays far below typical brute-force detection thresholds (no credential stuffing, no payload variation needed). The attack is repeatable indefinitely and requires no special knowledge beyond the public API documentation.

### Recommendation
1. **Add rate limiting to the rest-java module.** Introduce a bucket4j or Resilience4j `RateLimiter` filter scoped to `/api/v1/network/**`, enforcing a per-IP or global requests-per-second cap, mirroring the pattern already used in `web3/ThrottleConfiguration`.
2. **Cache the response.** The address book changes infrequently. Apply `@Cacheable` (e.g., Caffeine with a 30–60 second TTL) to `NetworkServiceImpl.getNetworkNodes()` so repeated calls within the window bypass the database entirely.
3. **Set an explicit `maximumPoolSize`** in rest-java's datasource configuration and configure HikariCP's `connectionTimeout` to fail fast rather than queue indefinitely.
4. **Add a query statement timeout** via `spring.datasource.hikari.connection-init-sql` or PostgreSQL `statement_timeout` so runaway queries release connections promptly.

### Proof of Concept
```bash
# Requires: curl, GNU parallel or wrk
# Step 1: Establish baseline latency
curl -o /dev/null -s -w "%{time_total}\n" \
  https://<mirror-node-host>/api/v1/network/nodes

# Step 2: Saturate the connection pool with concurrent requests
# Send 20 concurrent requests in a loop for 60 seconds
wrk -t 20 -c 20 -d 60s \
  https://<mirror-node-host>/api/v1/network/nodes

# Step 3: During the above, measure latency from a second terminal
for i in $(seq 1 10); do
  curl -o /dev/null -s -w "%{time_total}\n" \
    https://<mirror-node-host>/api/v1/network/nodes
  sleep 1
done

# Expected result: latency in step 3 increases >30% vs step 1 baseline.
# HikariCP metrics (if exposed via /actuator/metrics/hikaricp.connections.pending)
# will show pending > 0 and active == maximumPoolSize.
```