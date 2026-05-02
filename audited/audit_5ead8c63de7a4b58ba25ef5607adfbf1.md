### Title
Thread and Connection Pool Exhaustion via Unbounded DB Blocking in `TopicServiceImpl.findById()`

### Summary
`TopicServiceImpl.findById()` delegates directly to `topicRepository.findById()` with no application-level circuit breaker, timeout, or bulkhead. During any DB slowdown, every concurrent request to `GET /api/v1/topics/{id}` blocks a thread and holds a HikariCP connection for up to the full 20-second PostgreSQL statement timeout. An unprivileged attacker can flood this endpoint to exhaust the connection pool, amplifying any DB degradation into a full service outage for all users of the rest-java API.

### Finding Description
**Code path:**
- `rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java`, line 19–21
- `rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java` (plain `CrudRepository<Topic, Long>`, no timeout annotation)
- `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, line 32–37 (`topicService.findById()` called synchronously)

**Root cause:**
`findById()` is a single-line synchronous call with no Resilience4j `@CircuitBreaker`, `@TimeLimiter`, or `@Bulkhead` annotation, and no application-level rate limiting (unlike the `web3` module which uses bucket4j). The only DB-side bound is a PostgreSQL `statement_timeout` of 20,000 ms set at the role level (`alter user mirror_rest_java set statement_timeout to '20000'` in `charts/hedera-mirror/templates/secret-passwords.yaml`, line 125). HikariCP is configured via shared `CommonConfiguration` with no rest-java-specific pool cap visible in the codebase.

**Exploit flow:**
1. DB enters a degraded/slow state (natural event, or attacker-induced by flooding the same DB via other endpoints).
2. Attacker sends a sustained flood of `GET /api/v1/topics/<valid_id>` requests (no authentication required).
3. Each request acquires a HikariCP connection and blocks the serving thread for up to 20 seconds waiting for the DB.
4. The connection pool is exhausted; subsequent requests queue inside HikariCP waiting for `connectionTimeout` (HikariCP default: 30 s) before failing with a 500.
5. Only after 500 responses accumulate does the Traefik circuit breaker (`ResponseCodeRatio(500,600,0,600) > 0.25`) trip — but by then threads, connections, and the DB are already saturated.

**Why existing checks fail:**
- **Traefik circuit breaker** (`charts/hedera-mirror-rest-java/values.yaml`, line 151–152): fires on *error ratios*, not on *latency*. Slow-but-not-yet-timed-out queries produce no 5xx, so the breaker stays open during the entire 20-second blocking window.
- **PostgreSQL statement timeout (20 s)**: bounds per-query hold time but does not prevent N concurrent requests from each holding a connection for 20 s simultaneously.
- **GCP gateway `maxRatePerEndpoint: 250`** (`values.yaml`, line 56): 250 req/s × 20 s timeout = up to 5,000 simultaneous in-flight requests, far exceeding any realistic HikariCP pool size.
- **No application-level rate limiting** on the topics endpoint: the rest-java module has no bucket4j or equivalent throttle for `GET /api/v1/topics/{id}`.

### Impact Explanation
Connection pool exhaustion causes all rest-java endpoints (not just topics) to return 500 errors or hang, because HikariCP is shared. This is a full-service denial for the rest-java API. The attack amplifies any transient DB degradation into a prolonged outage. Classified Medium (griefing, no economic loss to network participants, no data exfiltration).

### Likelihood Explanation
The endpoint is publicly accessible with no authentication. The attacker needs only an HTTP client capable of sending concurrent requests. No exploit code, credentials, or insider knowledge are required. The attack is repeatable on demand whenever the DB is under any load. The 20-second statement timeout provides a long enough window to sustain pool exhaustion with a modest request rate.

### Recommendation
1. Add a Resilience4j `@TimeLimiter` (e.g., 5 s) and `@CircuitBreaker` to `TopicServiceImpl.findById()` so that slow DB calls fail fast and the circuit opens before pool exhaustion.
2. Add a `@Bulkhead` (semaphore or thread-pool isolation) to cap concurrent DB calls from this endpoint.
3. Apply application-level rate limiting (bucket4j, as used in `web3`) to `GET /api/v1/topics/{id}`.
4. Configure an explicit HikariCP `connectionTimeout` (e.g., 5 s) and `maximumPoolSize` in the rest-java datasource so pool exhaustion fails fast rather than queuing for 30 s.
5. Consider changing the Traefik circuit breaker expression to also include a latency threshold (e.g., `LatencyAtQuantileMS(50.0) > 2000`).

### Proof of Concept
```bash
# Precondition: DB is under load or artificially slowed (e.g., pg_sleep via another session)
# No credentials required

# Send 300 concurrent requests (exceeds typical pool size)
seq 1 300 | xargs -P 300 -I{} \
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/topics/0.0.1000"

# Observable result:
# 1. Response times climb to ~20 s (statement_timeout)
# 2. Subsequent requests to ANY rest-java endpoint return 500 (pool exhausted)
# 3. Traefik circuit breaker trips only after 500s accumulate (~25% threshold)
# 4. All rest-java endpoints remain degraded until pool drains
```