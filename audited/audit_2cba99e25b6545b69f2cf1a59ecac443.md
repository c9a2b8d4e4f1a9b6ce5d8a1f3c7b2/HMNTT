### Title
Unauthenticated DB Exhaustion via Uncached, Rate-Unlimited `TopicServiceImpl.findById()`

### Summary
`TopicServiceImpl.findById()` issues a live database query on every invocation with no `@Cacheable` annotation and no rate limiting on the `rest-java` module's `/api/v1/topics/{id}` endpoint. The only apparent protection, `ShallowEtagHeaderFilter`, does not prevent DB queries — it executes the full request pipeline first and only computes an ETag afterward for bandwidth savings. Any unauthenticated caller can sustain a continuous stream of DB reads against this endpoint, driving DB load above baseline without needing privileged access.

### Finding Description
**Code path:**
- `TopicController.getTopic()` → `topicService.findById(id.id())` → `TopicServiceImpl.findById()` → `topicRepository.findById(id.getId())`
- File: `rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java`, line 19–21
- File: `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, line 31–37

**Root cause:** `TopicServiceImpl` carries no `@Cacheable` or equivalent annotation. Every call to `findById()` unconditionally delegates to `topicRepository.findById(id.getId())`, issuing a live SQL query. Contrast this with the `web3` module, which has a full `ThrottleConfiguration` / `ThrottleManagerImpl` with bucket4j rate limiting — no equivalent exists in `rest-java`.

**Why `ShallowEtagHeaderFilter` is insufficient:** `RestJavaConfiguration.etagFilter()` registers a `ShallowEtagHeaderFilter` over `/api/*`. Spring's `ShallowEtagHeaderFilter` buffers the *already-rendered* response body and computes an MD5 ETag from it. The full controller → service → repository → DB round-trip executes before the filter ever inspects the ETag. A `304 Not Modified` saves bandwidth but does not save a DB query. Every request, even one with a matching `If-None-Match` header, still causes `topicRepository.findById()` to execute.

**No rate limiting in rest-java:** The `rest-java` config directory contains only `LoggingFilter`, `MetricsFilter`, `JacksonConfiguration`, `RestJavaConfiguration`, and `WebMvcConfiguration` — none of which implement request-rate throttling for the topics endpoint.

### Impact Explanation
An unauthenticated attacker sending a sustained moderate-rate stream of `GET /api/v1/topics/{id}` requests forces a live DB read per request with no possibility of a cache hit. Because the endpoint is publicly routable (Ingress path `/api/v1/topics/(\d+\.){0,2}\d+$` is exposed), the attacker can drive DB connection pool utilization and query throughput above the 30% baseline threshold. The `RestJavaHighDBConnections` Prometheus alert fires at 75% HikariCP pool utilization, confirming the operational concern is already recognized. Sustained load can degrade response times for all other DB-backed endpoints sharing the same pool.

### Likelihood Explanation
No authentication, no rate limiting, and no caching are required to exploit this. Any external user with network access to the mirror node's REST API can issue repeated GET requests to a known or enumerated topic ID. The exploit is trivially scriptable (`curl` in a loop or any HTTP benchmarking tool) and requires no special knowledge beyond a valid topic ID, which is publicly discoverable from the same API.

### Recommendation
1. Add `@Cacheable` to `TopicServiceImpl.findById()` with an appropriate TTL (topics are relatively static), mirroring the caching pattern already used in the `web3` module's `EntityRepository`.
2. Introduce request-rate limiting in the `rest-java` module for the `/api/v1/topics/{id}` endpoint, analogous to `ThrottleConfiguration` / `ThrottleManagerImpl` in `web3`.
3. Note that `ShallowEtagHeaderFilter` must not be relied upon as a DB-load mitigation — document or replace it with a proper server-side cache if DB offload is the goal.

### Proof of Concept
```bash
# Enumerate a valid topic ID from the public API, then:
TOPIC_ID=0.0.1234
BASE_URL=https://<mirror-node-host>

# Sustained moderate-rate loop — no authentication needed
while true; do
  curl -s -o /dev/null "$BASE_URL/api/v1/topics/$TOPIC_ID"
done

# Each iteration triggers:
#   TopicController.getTopic()
#     -> TopicServiceImpl.findById()          # no cache
#       -> topicRepository.findById(id)       # live DB query every time
#     -> entityService.findById(id)           # additional live DB query
#     -> customFeeService.findById(id)        # additional live DB query
# Three uncached DB queries per HTTP request.
# Monitor: hikaricp_connections_active / hikaricp_connections_max > 0.75
```