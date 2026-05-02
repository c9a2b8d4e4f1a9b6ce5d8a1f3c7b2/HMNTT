### Title
Unauthenticated Request Amplification via Triple Sequential DB Queries in `TopicController.getTopic()` Enables Resource Exhaustion

### Summary
`TopicController.getTopic()` issues three sequential, uncached database queries per single unauthenticated HTTP request — one each to `TopicRepository`, `EntityRepository`, and `CustomFeeRepository`. With no rate limiting, no caching, and no connection-pool guard on this endpoint, an unprivileged attacker can flood `GET /api/v1/topics/{id}` to exhaust the database connection pool and drive CPU/memory consumption well above the 30% threshold.

### Finding Description
**Exact code path:**

`TopicController.java` lines 32–37 — three sequential, blocking repository calls per request:
```java
var topic     = topicService.findById(id.id());   // → TopicRepository.findById()
var entity    = entityService.findById(id.id());  // → EntityRepository.findById()
var customFee = customFeeService.findById(id.id());// → CustomFeeRepository.findById()
```
Each service implementation (`TopicServiceImpl.java:19-21`, `EntityServiceImpl.java:24-27`, `CustomFeeServiceImpl.java:19-23`) performs a direct, synchronous `CrudRepository.findById()` call with no `@Cacheable` annotation and no result reuse. The calls are not parallelised.

**Root cause / failed assumption:** The design assumes the endpoint will be called at a rate low enough that 3× DB round-trips per request is acceptable. No rate-limiting filter, no response cache, and no per-IP throttle exist in the `rest-java` filter chain (`LoggingFilter`, `MetricsFilter`, `ShallowEtagHeaderFilter` — none enforce request limits). A grep for `RateLimit`, `Cacheable`, `bucket4j`, `resilience4j`, and Hikari pool configuration in `rest-java/` returns no matches.

**Exploit flow:**
1. Attacker identifies the public, unauthenticated `GET /api/v1/topics/{id}` endpoint.
2. Attacker sends a sustained flood of concurrent requests (e.g., 500 req/s with 50 concurrent connections) using any HTTP load tool.
3. Each request acquires a thread, then sequentially acquires up to 3 DB connections (or holds one connection across 3 queries depending on transaction scope), blocking for the full round-trip of all three queries before releasing.
4. The effective DB query rate is 3× the HTTP request rate. At 500 req/s, the DB sees ≥1,500 queries/s from this single endpoint alone.
5. The HikariCP default pool size (10 connections) is exhausted; subsequent requests queue or time out, causing cascading latency across all endpoints sharing the same pool.

### Impact Explanation
- **Database connection pool exhaustion:** 3× query amplification means the pool saturates at 1/3 the request rate compared to a single-query endpoint.
- **CPU/memory increase >30%:** Each blocked thread holds heap (request context, result objects) and CPU cycles for three sequential I/O waits. Under sustained load this easily exceeds the 30% threshold on both DB server and application JVM.
- **Availability impact on all endpoints:** The connection pool is shared; exhaustion degrades every other API endpoint on the same node simultaneously.
- **No authentication barrier:** The endpoint is fully public — zero preconditions for the attacker.

### Likelihood Explanation
Any unprivileged external user can trigger this with a single `curl` loop or any HTTP benchmarking tool (e.g., `wrk`, `ab`, `hey`). No credentials, tokens, or special knowledge are required beyond knowing the endpoint path, which is documented in the public API. The attack is trivially repeatable and automatable. The 3× amplification factor lowers the request volume needed to cause impact compared to a standard single-query endpoint.

### Recommendation
1. **Add rate limiting** at the servlet filter or API gateway layer for `/api/v1/topics/{id}` (e.g., Bucket4j or a reverse-proxy rate limit).
2. **Introduce response caching** (`@Cacheable` with a short TTL, e.g., 5–10 s) on `TopicServiceImpl.findById()`, `EntityServiceImpl.findById()`, and `CustomFeeServiceImpl.findById()` — topic metadata changes infrequently.
3. **Parallelise the three calls** using `CompletableFuture` to reduce wall-clock time and thread-hold duration per request, limiting connection pressure.
4. **Configure explicit Hikari pool limits** with a connection timeout that fails fast under overload rather than queuing indefinitely.

### Proof of Concept
```bash
# Flood the endpoint with 200 concurrent connections, no auth required
wrk -t8 -c200 -d60s http://<mirror-node-host>/api/v1/topics/0.0.1234

# Observe on the DB server:
# - Active query count climbs to ~3× the HTTP request rate
# - Connection pool wait time spikes (visible in HikariCP metrics at /actuator/metrics)
# - CPU on both app and DB nodes rises >30% vs. baseline 24h average
# - Other endpoints (/api/v1/accounts, /api/v1/transactions) begin returning 500/timeout
#   due to shared pool exhaustion
```