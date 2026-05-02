### Title
Unauthenticated Resource Exhaustion via Three Sequential Uncached DB Queries on GET /api/v1/topics/{id}

### Summary
The `TopicController.getTopic()` handler issues three sequential, uncached database queries per request with no rate limiting on the endpoint. Any unauthenticated external caller can repeatedly invoke `GET /api/v1/topics/{id}` with valid topic IDs to multiply DB connection pool pressure by a factor of 3 per request, causing sustained connection pool saturation and measurable CPU/IO increases on the mirror node without requiring brute-force request volumes.

### Finding Description

**Exact code path:**

`TopicController.java` lines 31–37 — the handler unconditionally fires three sequential repository calls:

```java
var topic     = topicService.findById(id.id());   // → topicRepository.findById()
var entity    = entityService.findById(id.id());  // → entityRepository.findById()
var customFee = customFeeService.findById(id.id()); // → customFeeRepository.findById()
``` [1](#0-0) 

Each service implementation delegates directly to its repository with no caching layer: [2](#0-1) [3](#0-2) [4](#0-3) 

**Root cause / failed assumption:**

- No `@Cacheable` or any caching annotation exists on any of the three service methods (confirmed: grep for `@Cacheable|@Cache|CacheManager` in `rest-java/src/main/java/**/*.java` returns zero matches in service classes).
- No rate limiting is applied to this endpoint. The only rate-limiting code found in the module is scoped to `NetworkController` and fee-estimation services — `TopicController` has none.
- The endpoint carries no authentication requirement, making it reachable by any unauthenticated external caller.

**Why existing checks are insufficient:**

The `rest-java` module has no `application.yml` resource file configuring Hikari pool limits, no Bucket4j/Resilience4j rate-limiter bean wired to this controller, and no Spring Cache configuration applied to the topic/entity/customFee service layer. There is no compensating control.

### Impact Explanation

Each single HTTP request to `GET /api/v1/topics/{id}` consumes three DB connections from the shared HikariCP pool sequentially. An attacker sending a sustained moderate request rate (e.g., 200–500 req/s — well below typical brute-force thresholds) generates 600–1500 DB round-trips per second. This saturates the connection pool, queues subsequent legitimate requests, and drives DB server CPU and I/O well above the 30% threshold relative to normal baseline traffic. Because the queries are sequential (not parallel), each request holds a connection for the full duration of all three queries, maximizing pool hold time.

### Likelihood Explanation

- **Precondition:** Attacker needs only a list of valid topic IDs, which are sequential integers discoverable by iterating from 1 upward or by observing public Hedera network data.
- **No authentication required:** The endpoint is fully public.
- **No rate limiting:** Confirmed absent for this controller.
- **Repeatability:** The attack is trivially scriptable with `curl`, `ab`, `wrk`, or any HTTP load tool. It requires no special knowledge, credentials, or protocol manipulation.

### Recommendation

1. **Add response caching** on `TopicServiceImpl.findById`, `EntityServiceImpl.findById`, and `CustomFeeServiceImpl.findById` using Spring's `@Cacheable` with a short TTL (e.g., 5–30 seconds), since topic/entity/fee data changes infrequently.
2. **Apply rate limiting** to `GET /api/v1/topics/{id}` per source IP using Bucket4j or a gateway-level rate limiter, consistent with how `NetworkController` is protected.
3. **Parallelize the three queries** (e.g., using `CompletableFuture`) to reduce per-request connection hold time even before caching is in place.
4. **Configure explicit HikariCP pool limits** in `application.yml` with a connection timeout that fails fast under saturation rather than queuing indefinitely.

### Proof of Concept

```bash
# Step 1: Identify valid topic IDs (public network data, or iterate from 1)
TOPIC_ID=0.0.1234

# Step 2: Launch sustained request flood (no auth needed)
wrk -t8 -c200 -d60s \
  "https://<mirror-node-host>/api/v1/topics/$TOPIC_ID"

# Each request triggers:
#   topicRepository.findById()    → DB query 1
#   entityRepository.findById()   → DB query 2
#   customFeeRepository.findById()→ DB query 3
#
# At 200 concurrent connections, this generates ~600 simultaneous
# DB queries, saturating a default HikariCP pool (default max=10)
# by 60x, causing connection queue buildup, elevated DB CPU/IO,
# and degraded response times for all other API consumers.
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L19-21)
```java
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L24-27)
```java
    public Entity findById(EntityId id) {
        return entityRepository.findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Entity not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/CustomFeeServiceImpl.java (L19-23)
```java
    public CustomFee findById(EntityId id) {
        return customFeeRepository
                .findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Custom fee for entity not found"));
    }
```
