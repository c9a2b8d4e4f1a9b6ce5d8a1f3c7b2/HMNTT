### Title
Unbounded Concurrent Requests to `GET /api/v1/topics/{id}` Exhaust HikariCP Connection Pool, Causing HTTP 500 for Legitimate Users

### Summary
The `TopicController.getTopic()` handler issues three sequential, uncached JPA/Hibernate queries per request (topic, entity, custom fee) through `TopicRepository.findById()` and sibling repositories, with no application-level rate limiting in the rest-java service. An unprivileged attacker flooding concurrent requests can exhaust the HikariCP connection pool (Spring Boot default: 10 connections), causing all subsequent legitimate requests to block until timeout and return HTTP 500.

### Finding Description
**Code path:**

- `TopicController.java` lines 31–37: `getTopic()` calls `topicService.findById()`, `entityService.findById()`, and `customFeeService.findById()` — three blocking DB round-trips per request, no caching, no semaphore.
- `TopicServiceImpl.java` line 20: `topicRepository.findById(id.getId())` — direct JPA call, no `@Cacheable`, no guard.
- `TopicRepository.java` line 7: plain `CrudRepository<Topic, Long>` — no custom query hints, no timeout override.

**Root cause:** No application-level rate limiting or concurrency cap exists in the rest-java service for this endpoint. The only infrastructure-level rate limit (`maxRatePerEndpoint: 250` in `charts/hedera-mirror-rest-java/values.yaml` line 56) is part of the GCP backend policy, which is gated behind `gateway.gcp.enabled: true` — itself defaulting to `false` (`global.gateway.enabled: false`, line 100). The Traefik middleware (`values.yaml` lines 158–163) configures only a circuit breaker and retry, not a rate limiter. No Hikari pool size is configured in rest-java, so Spring Boot's default of **10 connections** applies. With 3 DB calls per request and Tomcat's default 200-thread pool, an attacker needs only ~4–10 slow concurrent requests to saturate the pool; all remaining threads block on `HikariPool.getConnection()` until the 30-second default timeout, at which point Spring throws and the handler returns HTTP 500.

**Why existing checks fail:**
- GCP rate limit: disabled by default (`global.gateway.enabled: false`).
- Traefik circuit breaker: triggers *after* errors accumulate (>10% network error ratio or >25% 5xx ratio), not before pool exhaustion begins; retry config (`attempts: 3`) amplifies load.
- HPA: `hpa.enabled: false` by default — no horizontal scale-out.
- No `@RateLimiter`, no servlet filter, no Spring Security throttle in rest-java source.

### Impact Explanation
Connection pool exhaustion renders the entire rest-java service unavailable for all endpoints (not just `/topics/{id}`), because HikariCP is shared. Legitimate users receive HTTP 500 responses. The Prometheus alert `RestJavaHighDBConnections` (threshold 75%, `values.yaml` line 216) fires only after sustained saturation — it does not prevent the outage. Severity matches the stated scope: griefing/availability impact with no on-chain economic damage.

### Likelihood Explanation
Any unauthenticated external user can reach `GET /api/v1/topics/{id}` — no authentication is required. The attack requires only a standard HTTP load tool (e.g., `ab`, `wrk`, `hey`) sending ~50–200 concurrent requests/second from a single machine. The endpoint is publicly routed via ingress (`values.yaml` line 143). The attack is trivially repeatable and requires no special knowledge beyond the public API path.

### Recommendation
1. **Application-level rate limiting:** Add a `RateLimiter` (e.g., Resilience4j `@RateLimiter` or Bucket4j servlet filter) scoped to the rest-java service, independent of infrastructure gateway configuration.
2. **Increase and explicitly configure HikariCP pool size** in rest-java's Spring configuration to match expected concurrency, and set `connection-timeout` and `max-lifetime` explicitly.
3. **Add per-endpoint concurrency cap:** Use a `Semaphore` or Tomcat's `LimitFilter` to bound simultaneous in-flight requests to `/api/v1/topics/{id}`.
4. **Enable GCP rate limiting unconditionally** or provide an equivalent Traefik `InFlightReq` middleware for non-GCP deployments.
5. **Cache read-only topic lookups** with `@Cacheable` to reduce DB pressure per request.

### Proof of Concept
```bash
# Prerequisites: rest-java reachable at $HOST, no GCP gateway active
# Step 1: Flood concurrent requests (adjust -c for concurrency)
hey -c 200 -z 60s "http://$HOST/api/v1/topics/0.0.1234"

# Step 2: In parallel, send a legitimate request and observe HTTP 500
curl -v "http://$HOST/api/v1/topics/0.0.5678"
# Expected: HTTP 500 or connection timeout after HikariCP pool exhausted

# Step 3: Check Prometheus metric confirming pool saturation
# hikaricp_connections_active / hikaricp_connections_max → approaches 1.0
# http_server_requests_seconds_count{status="SERVER_ERROR"} spikes
```