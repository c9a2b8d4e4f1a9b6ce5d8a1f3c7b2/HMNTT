### Title
Unauthenticated Endpoint Allows Unbounded Database Index Scans via Non-Existent Topic ID Flooding

### Summary
The `TopicServiceImpl.findById()` method issues an unconditional primary-key database query for every incoming request with no rate limiting, no per-IP throttling, and no negative-result caching in the `rest-java` module. An unprivileged attacker can flood `/api/v1/topics/{id}` with arbitrary non-existent IDs, forcing repeated index scans on the `topic` table and degrading database I/O for all concurrent legitimate users.

### Finding Description
**Code path:**
- Controller entry point: `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, line 32–36 — `getTopic()` calls `topicService.findById(id.id())` with no guard.
- Service implementation: `rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java`, line 20 — `topicRepository.findById(id.getId()).orElseThrow(...)` issues a `SELECT … WHERE id = ?` on every call.
- Repository: `rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java` — plain `CrudRepository<Topic, Long>` with no custom query, no caching annotation.

**Root cause / failed assumption:** The design assumes an upstream rate-limiter will bound request volume. The `web3` module has a full `ThrottleManagerImpl` with bucket4j rate limiting, but the `rest-java` module has **no equivalent**. A search of all `rest-java/src/main/java/**` files finds zero occurrences of `rateLimit`, `RateLimit`, `Throttle`, or `@Cacheable` on the topic path. The Traefik middleware for `rest-java` (`charts/hedera-mirror-rest-java/values.yaml`, lines 150–155) configures only `circuitBreaker` (triggers on `ResponseCodeRatio(500,600,…) > 0.25`) and `retry` (3 attempts). HTTP 404 responses from non-existent topic IDs are **4xx**, so they never trip the circuit breaker and never trigger retries — the circuit breaker provides zero protection against this attack pattern.

**Exploit flow:**
1. Attacker sends a high-rate stream of `GET /api/v1/topics/<random_nonexistent_id>` requests (no authentication required).
2. Each request reaches `TopicServiceImpl.findById()` → `topicRepository.findById()` → PostgreSQL executes `SELECT … FROM topic WHERE id = <id>` using the primary-key B-tree index.
3. The query returns empty, `orElseThrow` raises `EntityNotFoundException`, and a 404 is returned — but the DB index scan already consumed I/O and a connection-pool slot.
4. At sufficient request rate, the HikariCP connection pool is saturated (monitored via `hikaricp_connections_active / hikaricp_connections_max` in the Prometheus rules at `charts/hedera-mirror-common/alerts/rules.yaml`, line 208), and legitimate queries queue or time out.

**Why existing checks fail:**
- `circuitBreaker` only opens on 5xx or network errors; 404s are transparent to it.
- `retry` is irrelevant (not triggered by 4xx).
- No per-IP or global request-rate cap exists anywhere in the `rest-java` request path.
- No negative-result cache prevents the same non-existent ID from hitting the DB repeatedly.

### Impact Explanation
Sustained flooding increases database I/O and exhausts the shared HikariCP connection pool, causing latency spikes and timeouts for all other `rest-java` endpoints (accounts, network, etc.) that share the same pool. This is a griefing/availability degradation impact with no direct economic loss to network participants, consistent with the stated Medium scope.

### Likelihood Explanation
No authentication, API key, or CAPTCHA is required. The endpoint is publicly reachable. The attacker needs only a single HTTP client capable of sustaining a high request rate (e.g., `ab`, `wrk`, or a simple loop). The attack is trivially repeatable from multiple source IPs to bypass any future IP-level controls. The absence of any rate-limiting code in the `rest-java` module makes this exploitable in the default deployment.

### Recommendation
1. **Add a global rate limiter to `rest-java`** analogous to the `web3` `ThrottleManagerImpl` — a bucket4j `OncePerRequestFilter` applied to all `/api/v1/**` routes.
2. **Add a Traefik `rateLimit` middleware** to `charts/hedera-mirror-rest-java/values.yaml` (mirroring the pattern in `charts/hedera-mirror-rosetta/values.yaml` lines 157–160) to enforce a per-source-IP request cap at the ingress layer.
3. **Cache negative (not-found) results** for a short TTL (e.g., 5 seconds) using Spring's `@Cacheable` on `TopicServiceImpl.findById()` to prevent repeated DB hits for the same non-existent ID.

### Proof of Concept
```bash
# Flood with non-existent topic IDs (requires no credentials)
for i in $(seq 1 100000); do
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/topics/9999999999" &
done
wait
# Observe: hikaricp_connections_active approaches hikaricp_connections_max
# Legitimate requests to /api/v1/accounts/... begin timing out
```