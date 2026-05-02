### Title
Unauthenticated Connection Pool Exhaustion via Unbounded Concurrent Requests to `/api/v1/network/registered-nodes`

### Summary
The `GET /api/v1/network/registered-nodes` endpoint in the `rest-java` module has no rate limiting, no authentication requirement, and issues a live database query on every request via `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()`. An unprivileged attacker can flood this endpoint with concurrent requests to exhaust the HikariCP connection pool, causing all subsequent legitimate node discovery requests to fail until the attack subsides.

### Finding Description
**Code path:**
- Controller: `rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java`, lines 173–187 — `getRegisteredNodes()` is a public, unauthenticated `@GetMapping` with no throttle annotation.
- Service: `rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java`, lines 139–152 — `getRegisteredNodes()` constructs a `PageRequest` and immediately calls the repository.
- Repository: `rest-java/src/main/java/org/hiero/mirror/restjava/repository/RegisteredNodeRepository.java`, lines 14–22 — `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()` executes a native SQL `SELECT *` against the `registered_node` table, holding a DB connection for the full query duration.

**Root cause:** The `rest-java` module has zero rate-limiting infrastructure. A grep across `rest-java/**` for `RateLimiter`, `rateLimit`, `RequestRateLimiter`, and `@RateLimit` returns no matches. The throttle/bucket4j machinery (`ThrottleConfiguration`, `ThrottleManagerImpl`, `ThrottleProperties`) exists exclusively in the `web3` module and is not applied to `rest-java` endpoints. The `RegisteredNodesRequest` enforces a `@Max(MAX_LIMIT)` on the `limit` parameter (bounding result size), but this does not limit the number of concurrent requests or the rate at which connections are consumed.

**Exploit flow:**
1. Attacker identifies the public, unauthenticated `GET /api/v1/network/registered-nodes` endpoint.
2. Attacker launches thousands of concurrent HTTP requests (e.g., using `ab`, `wrk`, or a simple script with async HTTP clients), optionally varying `registerednode.id` ranges to defeat any shallow caching.
3. Each request acquires a HikariCP connection and holds it for up to the configured `statementTimeout` (10,000 ms per `hiero.mirror.restJava.db.statementTimeout`).
4. The HikariCP pool (Spring Boot default: 10 connections; no custom `maximumPoolSize` is documented or found in `rest-java` resources) is saturated within the first wave of requests.
5. All subsequent requests — including those from legitimate registered nodes performing peer discovery — queue for a connection. Once the HikariCP `connectionTimeout` is exceeded, they receive a `500` error.
6. The attacker sustains the flood to keep the pool continuously exhausted.

**Why existing checks are insufficient:**
- `@Max(MAX_LIMIT)` on `limit` only bounds result set size, not request concurrency.
- `statementTimeout = 10000ms` limits individual query duration but means each malicious request holds a connection for up to 10 seconds — a single wave of 10 concurrent requests saturates a default-sized pool for 10 seconds.
- No `@Transactional(readOnly=true, timeout=...)` short-circuit exists.
- No IP-based or global request-rate throttle is present in `rest-java`.
- The Prometheus alert `RestJavaHighDBConnections` (fires at >75% utilization for 5 minutes) is a monitoring signal, not a protective control.

### Impact Explanation
When the connection pool is exhausted, the mirror node returns errors to all callers of `/api/v1/network/registered-nodes`. Registered nodes (block nodes, mirror nodes, RPC relays) that rely on this endpoint for peer discovery cannot obtain up-to-date service endpoint information. If this mirror node instance is a primary or sole discovery endpoint for a set of registered nodes, 100% of those nodes are denied peer information for the duration of the attack. Across a deployment where multiple registered nodes query the same mirror node, this satisfies the ≥30% network processing node disruption threshold described in the scope.

### Likelihood Explanation
The attack requires no credentials, no special knowledge beyond the public API spec (documented in `rest/api/v1/openapi.yml`), and no brute force. Any attacker with network access to the mirror node's HTTP port can execute it with commodity load-testing tools. It is repeatable and sustainable at negligible cost. The absence of any rate-limiting layer in `rest-java` means there is no automated defense to overcome.

### Recommendation
1. **Add a rate-limiting filter to `rest-java`**: Port the bucket4j-based `ThrottleConfiguration`/`ThrottleManagerImpl` pattern from the `web3` module, or add a Spring Cloud Gateway / servlet filter that enforces a per-IP and global requests-per-second cap on all `rest-java` endpoints.
2. **Reduce `statementTimeout`** for the `registered_node` query to a value well below 10 seconds (e.g., 2–3 seconds), limiting how long each request holds a connection.
3. **Increase the HikariCP pool size** with an explicit `spring.datasource.hikari.maximum-pool-size` setting appropriate for expected concurrency, and set `connectionTimeout` to a low value (e.g., 2 seconds) so queued requests fail fast rather than piling up.
4. **Add response caching** (e.g., a short-lived in-memory or Redis cache) for the registered-nodes list, so repeated identical queries do not each hit the database.
5. **Deploy an ingress-level rate limiter** (e.g., Nginx `limit_req`, Kubernetes ingress annotations, or a WAF rule) as a defense-in-depth layer upstream of the application.

### Proof of Concept
```bash
# Saturate the connection pool with concurrent requests
# Requires: wrk (https://github.com/wg/wrk) or equivalent

wrk -t 50 -c 500 -d 60s \
  "http://<mirror-node-host>:8080/api/v1/network/registered-nodes?limit=100"

# Simultaneously, observe legitimate requests failing:
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    "http://<mirror-node-host>:8080/api/v1/network/registered-nodes" &
done
wait
# Expected: mix of 200 (before pool exhaustion) and 500 (after pool exhaustion)
```

Expected result: once the 500-connection flood is sustained, legitimate single requests return HTTP 500 with a HikariCP connection timeout error, confirming pool exhaustion and denial of node discovery service.