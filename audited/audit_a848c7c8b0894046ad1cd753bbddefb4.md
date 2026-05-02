### Title
Thread and Connection Pool Exhaustion via Unbounded Blocking DB Calls in `getTopic()` During Network Partition

### Summary
`TopicController.getTopic()` makes three sequential, synchronous JPA repository calls with no application-level circuit breaker, bulkhead, or per-IP in-flight request limit. During a database network partition, every incoming request to `GET /api/v1/topics/{id}` blocks a Tomcat thread and a HikariCP connection for up to the full statement timeout (10–20 s). The Traefik retry middleware (3 attempts) multiplies each client request into four server-side blocking calls. An unprivileged attacker who floods this endpoint during a partition can exhaust both pools, rendering the entire service permanently unresponsive until the partition resolves and all queued requests drain.

### Finding Description

**Exact code path:**

`TopicController.getTopic()` (lines 32–37) calls three services sequentially with no timeout, circuit-breaker, or bulkhead annotation:

```java
var topic     = topicService.findById(id.id());   // blocks → TopicRepository.findById()
var entity    = entityService.findById(id.id());  // blocks → EntityRepository.findById()
var customFee = customFeeService.findById(id.id()); // blocks → CustomFeeRepository.findById()
```

Each service implementation (e.g. `TopicServiceImpl.findById()`, line 20) delegates directly to a Spring Data JPA repository backed by HikariCP — a fully synchronous, blocking call with no fast-fail path.

**Root cause — failed assumption:** The design assumes the database is always reachable within the statement timeout. There is no application-level circuit breaker to short-circuit calls once the DB is known to be unreachable, and no bulkhead to cap the number of concurrent in-flight requests per client.

**Confirmed absence of mitigations in `rest-java`:**
- `grep` across all `rest-java/**/*.java` returns zero matches for `@CircuitBreaker`, `@Bulkhead`, `@RateLimiter`, `@TimeLimiter`, or any Resilience4j annotation.
- The Traefik middleware for `rest-java` (`charts/hedera-mirror-rest-java/values.yaml`, lines 158–163) contains only `circuitBreaker` and `retry` — no `inFlightReq` per-IP limit. By contrast, the graphql service has `inFlightReq: amount: 5` and rosetta has both `inFlightReq` and `rateLimit`.
- The Traefik retry middleware is configured as `attempts: 3, initialInterval: 100ms`, meaning each client request that times out is retried three additional times server-side — a 4× amplification of thread and connection consumption.
- HPA is disabled by default (`hpa.enabled: false`), so no auto-scaling absorbs the load.

**Why the Traefik circuit breaker is insufficient:**
The Traefik circuit breaker expression is `NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25`. It is reactive: it only trips after 25% of responses are already 5xx. During the window before it trips, all requests block inside the application. After it trips, it prevents new requests from reaching the app but does **not** free the threads and connections already blocked inside the JVM — those remain held until their individual statement timeouts expire (10–20 s per the `statementTimeout` default of 10,000 ms documented in `docs/configuration.md` line 630, and the Helm SQL template setting `statement_timeout` to `20000` ms for `restJavaUsername`).

### Impact Explanation

During a DB partition, an attacker sending a sustained flood of `GET /api/v1/topics/{id}` requests (no authentication required — public endpoint) will:

1. Exhaust the HikariCP connection pool (default pool size is not explicitly set for rest-java, so HikariCP defaults apply — typically 10 connections). Each blocked request holds a connection for up to 10–20 s.
2. Exhaust the Tomcat/Spring thread pool. With 4× retry amplification, 50 concurrent client requests generate 200 server-side blocking threads.
3. Cause all other endpoints sharing the same JVM and connection pool to become unresponsive — a full service outage, not just degradation of the topics endpoint.
4. Prevent recovery: even after the DB partition resolves, the backlog of queued requests continues to consume resources, delaying restoration of normal service.

The `RestJavaHighDBConnections` Prometheus alert only fires after 5 minutes at >75% utilization — well after the service is already unresponsive.

### Likelihood Explanation

- **Precondition**: A DB network partition must exist. This is an external condition (infrastructure failure, maintenance, misconfiguration) — not caused by the attacker.
- **Attacker capability**: Zero privilege required. The `GET /api/v1/topics/{id}` endpoint is public. Any internet-accessible client can send requests.
- **Feasibility**: A single attacker with a modest number of concurrent HTTP connections (e.g., 50–100) is sufficient to exhaust the connection pool given the 10–20 s blocking duration per request and 4× retry amplification.
- **Repeatability**: The attack is trivially repeatable for the entire duration of the partition. The attacker does not need to sustain a high request rate — they only need to keep enough concurrent requests in flight to saturate the pool.
- **Detection gap**: The Traefik circuit breaker and Prometheus alerts are reactive and slow (5-minute windows), providing no real-time protection.

### Recommendation

1. **Add an application-level circuit breaker** using Resilience4j `@CircuitBreaker` on `TopicServiceImpl.findById()`, `EntityServiceImpl.findById()`, and `CustomFeeServiceImpl.findById()`. Configure it to open after a small number of consecutive DB failures and fast-fail with a 503 response instead of blocking.

2. **Add a `@TimeLimiter` or `@Bulkhead`** annotation on `getTopic()` to cap the maximum time any single request can block and limit concurrent in-flight calls to the DB layer.

3. **Add `inFlightReq` per-IP limiting** to the rest-java Traefik middleware (matching the pattern already used by graphql and rosetta):
   ```yaml
   - inFlightReq:
       amount: 5
       sourceCriterion:
         ipStrategy:
           depth: 1
   ```

4. **Remove or reduce the retry middleware** for this endpoint, or make it conditional on non-timeout errors only. Retrying timed-out DB calls amplifies pool exhaustion.

5. **Enable HPA** (`hpa.enabled: true`) so the service can scale out under load.

### Proof of Concept

**Preconditions:** DB network partition is active (e.g., firewall rule blocking port 5432 from the rest-java pod).

**Steps:**

```bash
# Send 100 concurrent requests to the topics endpoint (no auth required)
# Each will block for ~10-20s; Traefik retries each 3 more times
seq 1 100 | xargs -P 100 -I{} \
  curl -s -o /dev/null -w "%{http_code}\n" \
  "https://<mirror-node-host>/api/v1/topics/0.0.1234"
```

**Expected result:**
- Initial requests return after ~10–20 s with HTTP 500 (statement timeout).
- Subsequent requests hang indefinitely (HikariCP connection acquisition timeout, default 30 s) as the pool is exhausted.
- All other `rest-java` endpoints (e.g., `/api/v1/network/fees`) become unresponsive.
- After the DB partition resolves, the service takes an additional 30–60 s to drain the backlog before recovering.
- The Traefik circuit breaker may trip during this window but does not accelerate recovery of the already-blocked threads. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L31-37)
```java
    @GetMapping(value = "/{id}")
    Topic getTopic(@PathVariable EntityIdNumParameter id) {
        var topic = topicService.findById(id.id());
        var entity = entityService.findById(id.id());
        var customFee = customFeeService.findById(id.id());
        return topicMapper.map(customFee, entity, topic);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L18-21)
```java
    @Override
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L107-109)
```yaml
hpa:
  behavior: {}
  enabled: false
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L158-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** docs/configuration.md (L630-630)
```markdown
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
```

**File:** charts/hedera-mirror/templates/secret-passwords.yaml (L125-125)
```yaml
    alter user {{ $restJavaUsername }} set statement_timeout to '20000';
```
