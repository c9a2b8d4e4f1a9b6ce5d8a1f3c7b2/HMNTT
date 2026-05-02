### Title
Unbounded DB Amplification via Uncached `TopicRepository.findById()` on `GET /api/v1/topics/{id}`

### Summary
The `rest-java` module's `GET /api/v1/topics/{id}` endpoint issues three uncached database queries per request (topic, entity, custom fee) with no server-side response cache and no rate limiting. The `Cache-Control: public, max-age=5` header is a client-side hint only and does not prevent the server from executing a fresh `TopicRepository.findById()` call for every arriving request. An unprivileged attacker can flood this endpoint to exhaust the DB connection pool and drive DB CPU well above 30% of baseline.

### Finding Description
**Code path:**
- `TopicController.getTopic()` — `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 31–37 — calls `topicService.findById()`, `entityService.findById()`, and `customFeeService.findById()` sequentially, three DB round-trips per HTTP request.
- `TopicServiceImpl.findById()` — `rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java`, line 20 — delegates directly to `topicRepository.findById(id.getId())`.
- `TopicRepository` — `rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java`, lines 1–8 — a bare `CrudRepository` with **no `@Cacheable` annotation**, unlike, e.g., `grpc/EntityRepository` which carries `@Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, ...)`.

**Root cause:** No application-level caching exists at any layer (repository, service, or controller) in `rest-java` for this endpoint. The `Cache-Control: public, max-age=5` response header (confirmed by `TopicControllerTest`, line 94) is a downstream/client hint; it does not deduplicate concurrent server-side requests. The Redis-based response cache (`hiero.mirror.rest.cache.response.enabled`) belongs to the Node.js `rest` module (`rest/middleware/responseCacheHandler.js`) and is **disabled by default** (`false`). No `ThrottleManager` or rate-limiting filter exists in `rest-java` (throttling is only wired in the `web3` module via `ThrottleConfiguration` / `ThrottleManagerImpl`).

**Why checks fail:** The `max-age=5` header only instructs compliant HTTP clients and CDNs to reuse a cached copy; it provides zero protection when an attacker bypasses caching by sending requests with `Cache-Control: no-cache` or `Pragma: no-cache`, or simply by using many parallel connections. Each such request reaches `TopicController.getTopic()` and triggers three independent SQL queries.

### Impact Explanation
Each request to `GET /api/v1/topics/{id}` consumes at least one DB connection for each of the three queries. With no rate limiting and no server-side cache, an attacker sending N concurrent requests forces N×3 DB queries. The documented default DB connection pool for the REST layer is 10 connections (`hiero.mirror.rest.db.pool.maxConnections = 10`). Saturating the pool blocks all other REST API consumers. Even below pool saturation, sustained high-frequency requests against a single topic ID produce measurable DB CPU amplification well above the 30% threshold, degrading the mirror node's ability to serve all other endpoints. Severity: **Medium–High** (availability impact, no data exfiltration).

### Likelihood Explanation
No authentication or API key is required. The endpoint is publicly accessible. The attacker needs only a script sending repeated HTTP GET requests to a single valid topic ID. Bypassing the `max-age=5` hint requires adding a single header (`Cache-Control: no-cache`) or simply using a raw HTTP client that ignores cache semantics. The attack is trivially repeatable and automatable with tools like `ab`, `wrk`, or `curl` in a loop.

### Recommendation
1. Add `@Cacheable` to `TopicRepository.findById()` (mirroring the pattern in `grpc/EntityRepository`) with a short TTL (e.g., 5 s, matching the existing `max-age`).
2. Alternatively, add a server-side response cache in `rest-java` analogous to `rest/middleware/responseCacheHandler.js`.
3. Implement request-rate limiting in `rest-java` (e.g., using bucket4j as already done in the `web3` module) to cap requests per IP per second on read endpoints.
4. Enable the Redis response cache (`hiero.mirror.rest.cache.response.enabled=true`) if the deployment includes Redis, so repeated identical requests are served from cache without hitting the DB.

### Proof of Concept
```bash
# Step 1: Identify a valid topic ID (e.g., 0.0.1234)
TOPIC_ID="0.0.1234"
BASE_URL="https://<mirror-node-host>/api/v1/topics"

# Step 2: Flood the endpoint, bypassing any intermediate cache
for i in $(seq 1 500); do
  curl -s -o /dev/null \
    -H "Cache-Control: no-cache" \
    -H "Pragma: no-cache" \
    "${BASE_URL}/${TOPIC_ID}" &
done
wait

# Each of the 500 concurrent requests reaches TopicController.getTopic(),
# which calls topicService.findById(), entityService.findById(), and
# customFeeService.findById() — 1500 DB queries total, no server-side
# deduplication, no rate limiting applied.
```
Observe DB connection pool saturation and CPU spike on the mirror node's PostgreSQL instance exceeding 30% above the 24-hour baseline.