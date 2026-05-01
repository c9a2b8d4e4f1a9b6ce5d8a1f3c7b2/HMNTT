### Title
Unbounded Unauthenticated Request Amplification via Uncached, Unthrottled `TopicRepository.findById()` in rest-java

### Summary
The `GET /api/v1/topics/{id}` endpoint in the `rest-java` module invokes `TopicRepository.findById()` on every request with no result caching and no application-level rate limiting. Any unauthenticated external user can send an unbounded burst of requests for a single valid topic ID, causing a proportional number of `SELECT` queries against the `topic` table, linearly increasing database CPU utilization and degrading service for all users sharing the same database.

### Finding Description
**Code path:**

- `TopicController.getTopic()` (`rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 31–37) receives every `GET /api/v1/topics/{id}` request with no authentication or rate-limiting guard.
- It calls `topicService.findById(id.id())` which delegates to `TopicServiceImpl.findById()` (`rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java`, line 20): `topicRepository.findById(id.getId()).orElseThrow(...)`.
- `TopicRepository` (`rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java`, lines 1–9) is a bare `CrudRepository<Topic, Long>` with **no `@Cacheable` annotation** — confirmed by grep returning zero matches for `@Cacheable|CacheManager|EnableCaching` across all of `rest-java/`.

**Root cause — two absent controls:**

1. **No caching.** The `grpc` module's `EntityRepository` and the `web3` module's `ContractRepository`/`EntityRepository` all carry `@Cacheable` annotations backed by Caffeine. The `rest-java` `TopicRepository` has none. Every call issues a fresh `SELECT` to the database.

2. **No rate limiting.** The `web3` module has a full `ThrottleConfiguration` / `ThrottleManagerImpl` (bucket4j, 500 req/s default). The `rest-java` module's only registered filters are `LoggingFilter`, `MetricsFilter`, and `ShallowEtagHeaderFilter` — none of which throttle requests. The `ShallowEtagHeaderFilter` computes an ETag *after* the response body is generated, so the DB query executes unconditionally on every request regardless of `If-None-Match` headers.

**Failed assumption:** The design assumes that infrastructure-level rate limiting (e.g., ingress/nginx) will protect the database. The Helm chart (`charts/hedera-mirror-rest-java/`) defines an ingress template but no `nginx.ingress.kubernetes.io/limit-rps` or equivalent annotation in `values.yaml`, leaving the application fully exposed at the application layer.

### Impact Explanation
Each request to `GET /api/v1/topics/{id}` unconditionally executes a `SELECT` against the `topic` table. A single attacker sending N requests/second causes N database reads/second for a query that returns identical data. At sufficient volume this saturates database CPU, increases query latency for all other API consumers (topics, entities, custom fees), and can cause connection pool exhaustion. Because the `topic` table is a mirror-node table (not a consensus-critical component), the impact is service degradation of the mirror node API — no on-chain state is affected. This matches the stated scope: griefing with no economic damage to network participants.

### Likelihood Explanation
No preconditions are required. Any unauthenticated HTTP client can reach the endpoint. A single machine with a modest HTTP benchmarking tool (e.g., `wrk`, `ab`, `hey`) can sustain thousands of requests per second. The attack is trivially repeatable, requires no special knowledge beyond a valid topic ID (which is publicly enumerable from the same API), and produces no error that would alert the attacker to back off.

### Recommendation
Apply both controls within the `rest-java` module:

1. **Add `@Cacheable` to `TopicRepository.findById()`** (mirroring the pattern in `grpc`'s `EntityRepository`) with a short TTL (e.g., 30 s) to absorb repeated reads for the same ID.
2. **Add application-level rate limiting** to the `rest-java` module — either a servlet filter using bucket4j (matching the `web3` pattern in `ThrottleConfiguration`) or Spring's `HandlerInterceptor` — enforcing a per-IP or global requests-per-second ceiling on `/api/v1/**`.
3. **Add ingress-level rate limiting** annotations to `charts/hedera-mirror-rest-java/values.yaml` as a defence-in-depth layer.

### Proof of Concept
```bash
# Precondition: obtain any valid topic ID (publicly enumerable)
TOPIC_ID=1

# Flood the endpoint from a single unauthenticated client
wrk -t 8 -c 200 -d 60s \
    "https://<mirror-node-host>/api/v1/topics/${TOPIC_ID}"

# Observable result:
# - Database CPU rises linearly with request rate
# - `spring_data_repository_invocations_seconds_count{repository="TopicRepository"}`
#   metric increments on every request (no cache hits)
# - Latency for all other rest-java endpoints increases as DB connection pool saturates
```