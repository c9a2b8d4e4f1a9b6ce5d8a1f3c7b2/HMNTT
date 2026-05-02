### Title
Unauthenticated Request Flood via `TopicRepository.findById()` Exhausts HikariCP Pool and Queues Threads, Causing Memory Exhaustion

### Summary
The `GET /api/v1/topics/{id}` endpoint is publicly accessible with no authentication, no per-IP in-flight request limit, and no application-level bulkhead. Each request synchronously blocks a Tomcat thread waiting for a HikariCP connection. An attacker flooding this endpoint exhausts the bounded connection pool, causing all subsequent threads to queue waiting up to 30 seconds per request, accumulating thread stacks and request objects that can increase JVM memory consumption by 30% or more.

### Finding Description
**Code path:**

- `TopicController.getTopic()` (`rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 31–37) handles `GET /api/v1/topics/{id}` with no authentication or rate-limiting guard.
- It calls `TopicServiceImpl.findById()` (`rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java`, line 20), which calls `topicRepository.findById(id.getId())` — a synchronous, blocking Spring Data `CrudRepository` call.
- `TopicRepository` (`rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java`) is a plain `CrudRepository` interface with no timeout, no `@Bulkhead`, no `@CircuitBreaker`, and no `@TimeLimiter` annotation.

**Root cause — three compounding gaps:**

1. **No application-level bulkhead/semaphore.** Unlike the `web3` module which has `ThrottleManagerImpl` with Bucket4j rate limiting, the `rest-java` module has no equivalent. The `ImporterConfiguration` uses `@EnableResilientMethods` but the rest-java module does not apply any resilience annotation to `TopicServiceImpl`.

2. **No `inFlightReq` Traefik middleware for rest-java.** The `hedera-mirror-rest-java` Helm chart (`charts/hedera-mirror-rest-java/values.yaml`, lines 150–155) defines only a `circuitBreaker` (error-ratio based) and `retry` middleware. Critically, it lacks the `inFlightReq` middleware that IS present in `hedera-mirror-graphql/values.yaml` (lines 138–141) and `hedera-mirror-rosetta/values.yaml` (lines 152–156), which limit concurrent requests per source IP.

3. **Bounded HikariCP pool with unbounded HTTP thread queue.** `CommonConfiguration` (`common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java`, lines 60–95) creates a HikariCP pool from `spring.datasource.hikari` config. HikariCP defaults to `maximumPoolSize=10` and `connectionTimeout=30000ms`. Spring Boot's embedded Tomcat defaults to 200 worker threads. When all 10 DB connections are held, up to 190 additional Tomcat threads block in HikariCP's wait queue for up to 30 seconds each.

**Why existing checks fail:**

The Traefik circuit breaker (`NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25`) only trips on network errors or 5xx response ratios. A slow DB that is still responding (just slowly) does not trigger it. The HikariCP `connectionTimeout` eventually throws a `SQLTimeoutException` (producing a 500), but by then hundreds of threads are already blocked, and the circuit breaker only opens after the error ratio threshold is crossed — not proactively.

### Impact Explanation
Each blocked Tomcat thread holds a stack (default 512 KB–1 MB on JVM). With 200 threads blocked waiting for DB connections, that is 100–200 MB of thread stack memory alone, plus heap for each queued `HttpServletRequest` object, Spring MVC `DispatcherServlet` context, and JPA session objects. On a node with a baseline heap of 256–512 MB (typical for a REST microservice), this represents a 30–80% increase in memory consumption. Sustained flooding can trigger OOM kills, cascading to other services sharing the node.

### Likelihood Explanation
No privileges are required. The endpoint `GET /api/v1/topics/{id}` is publicly documented in the OpenAPI spec (`rest/api/v1/openapi.yml`, line 1125) and is reachable from the internet via the Traefik ingress. A single attacker with a modest HTTP flood tool (e.g., `wrk`, `hey`, or `ab`) sending hundreds of concurrent requests per second can saturate the 10-connection HikariCP pool within milliseconds. The attack is repeatable, requires no authentication, and no API key. The absence of `inFlightReq` (present in sibling services) makes this a straightforward gap to exploit.

### Recommendation
1. **Add `inFlightReq` Traefik middleware** to `charts/hedera-mirror-rest-java/values.yaml` (matching the pattern in `hedera-mirror-rosetta/values.yaml` lines 152–156) to cap concurrent requests per source IP.
2. **Add a Resilience4j `@Bulkhead` annotation** (semaphore type) on `TopicServiceImpl.findById()` to cap concurrent in-flight DB calls at the application level, returning HTTP 429 when the limit is exceeded.
3. **Configure HikariCP `connectionTimeout`** to a lower value (e.g., 5 seconds) so threads fail fast rather than queuing for 30 seconds, reducing the window for thread accumulation.
4. **Set Tomcat `server.tomcat.max-threads`** and `server.tomcat.accept-count` explicitly to prevent unbounded thread and accept-queue growth.

### Proof of Concept
```
# Prerequisites: rest-java service accessible at $HOST, any valid topic ID $TOPIC_ID
# Step 1: Flood the endpoint with high concurrency
wrk -t 50 -c 500 -d 60s http://$HOST/api/v1/topics/$TOPIC_ID

# Step 2: Monitor JVM memory on the rest-java pod
kubectl exec -n <namespace> <restjava-pod> -- \
  jcmd 1 VM.native_memory summary

# Step 3: Observe HikariCP pending connections metric
# Expected: hikaricp_connections_pending > 0 sustained, 
#           hikaricp_connections_active == maximumPoolSize (10)
# Expected: JVM heap + thread memory increases >= 30% vs baseline

# Step 4: Confirm no rate-limit rejection (HTTP 429) is returned —
#         all requests either succeed (200) or timeout (500 after 30s),
#         confirming absence of any bulkhead or inFlightReq guard.
```