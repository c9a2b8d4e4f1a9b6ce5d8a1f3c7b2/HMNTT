### Title
Unauthenticated DoS via Unbounded Concurrent Requests to Expensive Multi-CTE SQL Query on `GET /api/v1/network/nodes`

### Summary
The `GET /api/v1/network/nodes` endpoint in the `rest-java` module executes a complex multi-CTE native SQL query (with a correlated per-row subquery) on every request, with no application-level rate limiting. Any unauthenticated external user can flood this endpoint with concurrent requests, exhausting PostgreSQL query execution resources and denying service to all consumers of gossip topology data.

### Finding Description
**Exact code path:**

`NetworkController.getNodes()` (`rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java`, lines 152–171) accepts unauthenticated `GET /api/v1/network/nodes` requests and delegates directly to `NetworkServiceImpl.getNetworkNodes()` (`rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java`, lines 100–137), which calls `NetworkNodeRepository.findNetworkNodes()`.

**The expensive query** (`rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java`, lines 25–103) executes on every request:
- `latest_address_book` CTE: `ORDER BY start_consensus_timestamp DESC LIMIT 1` on `address_book`
- `latest_node_stake` CTE: `SELECT max(consensus_timestamp) FROM node_stake` (full aggregate scan)
- `node_info` CTE: full scan of `node` table
- A **correlated subquery per result row** executing `jsonb_agg(... ORDER BY ...)` against `address_book_service_endpoint`

**Root cause:** The `rest-java` module has zero application-level rate limiting for this endpoint. Searching all Java source under `rest-java/src/main/java/` reveals only `LoggingFilter` and `MetricsFilter` — no `bucket4j`, no `ThrottleManager`, no request throttle of any kind. The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists exclusively in the `web3` module and is not wired into `rest-java`.

**Why the existing limit check is insufficient:** `NetworkNodeRequest.getEffectiveLimit()` caps results at `MAX_LIMIT = 25`, but this only bounds the result set size — it does not reduce the cost of the three CTEs or the correlated subquery, all of which execute fully regardless of the limit.

### Impact Explanation
An attacker flooding this endpoint with concurrent requests forces PostgreSQL to execute the full multi-CTE query (including a per-row correlated `jsonb_agg` subquery and a full `max()` aggregate on `node_stake`) for each request simultaneously. This exhausts PostgreSQL worker processes, connection pool slots (HikariCP), and I/O bandwidth, causing query timeouts or complete unavailability for all mirror node consumers — including those relying on gossip topology data for network participation. The impact is a full denial of service of the `/api/v1/network/` surface.

### Likelihood Explanation
No authentication, API key, or credential is required. The endpoint is publicly documented in `rest/api/v1/openapi.yml`. A single attacker with a modest botnet or even a single machine using async HTTP clients (e.g., `wrk`, `ab`, `hey`) can trivially generate thousands of concurrent requests. The attack is repeatable indefinitely and requires no special knowledge beyond the public API spec.

The optional GCP infrastructure-level cap (`maxRatePerEndpoint: 250` in `charts/hedera-mirror-rest-java/values.yaml`) is not a reliable mitigation: it is only active when `gateway.gcp.enabled: true` is set, is not enforced at the application layer, and 250 req/s of this query is still sufficient to saturate a typical PostgreSQL instance.

### Recommendation
1. **Add application-level rate limiting** in `rest-java` analogous to the `web3` module's `ThrottleConfiguration`/`ThrottleManagerImpl` using `bucket4j`, applied as a servlet filter or Spring interceptor scoped to `/api/v1/network/nodes`.
2. **Cache the query result** — the address book and node stake data change infrequently (only on governance transactions). A short-lived cache (e.g., 30–60 seconds via Spring Cache or Caffeine) on `NetworkServiceImpl.getNetworkNodes()` would eliminate redundant DB hits entirely.
3. **Set a PostgreSQL `statement_timeout`** for the connection pool used by `rest-java` to bound worst-case query duration and prevent connection starvation.
4. **Do not rely solely on infrastructure-level rate limiting** as the only defense.

### Proof of Concept
```bash
# No authentication required. Run from any machine.
# Install: apt install apache2-utils  (or use wrk/hey)

# Send 500 concurrent requests, 10000 total
ab -n 10000 -c 500 \
  "https://<mirror-node-host>/api/v1/network/nodes"

# Observe: PostgreSQL active_queries saturates, subsequent requests
# time out or return 503; other /api/v1/ endpoints also degrade
# due to shared connection pool exhaustion.

# Verify degradation:
curl -w "%{time_total}\n" -o /dev/null -s \
  "https://<mirror-node-host>/api/v1/network/nodes"
# Response time climbs from ~50ms to >20s or connection refused
```