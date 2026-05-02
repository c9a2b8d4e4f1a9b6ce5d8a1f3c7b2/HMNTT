### Title
Unauthenticated Request Amplification via `/api/v1/topics/{id}` Triggers Three Uncached DB Queries Per Request with No Rate Limiting in rest-java

### Summary
The `TopicController.getTopic()` handler unconditionally executes three sequential database queries per HTTP GET request against three separate tables (`topic`, `entity`, `custom_fee`). The `rest-java` module contains no rate-limiting mechanism, and the service layer has no application-level caching for these queries. Any unauthenticated external user can flood this endpoint to generate a 3× DB query amplification factor, exhausting the shared database connection pool and degrading service for all users.

### Finding Description
**Exact code path:**

`TopicController.getTopic()` at lines 31–37:
```java
@GetMapping(value = "/{id}")
Topic getTopic(@PathVariable EntityIdNumParameter id) {
    var topic = topicService.findById(id.id());       // DB query 1: topic table
    var entity = entityService.findById(id.id());     // DB query 2: entity table
    var customFee = customFeeService.findById(id.id()); // DB query 3: custom_fee table
    return topicMapper.map(customFee, entity, topic);
}
```

Each service implementation goes directly to the repository with no caching:
- `TopicServiceImpl.findById()` → `topicRepository.findById(id.getId())`
- `EntityServiceImpl.findById()` → `entityRepository.findById(id.getId())`
- `CustomFeeServiceImpl.findById()` → `customFeeRepository.findById(id.getId())`

**Root cause — failed assumption:** The design assumes an upstream CDN or infrastructure-level rate limiter will absorb abuse. The `rest-java` module itself has no rate-limiting filter (the `ThrottleConfiguration`/`ThrottleManagerImpl` exist only in the `web3` module). The `WebMvcConfiguration`, `RestJavaConfiguration`, and `LoggingFilter` in `rest-java/config/` contain no throttling logic. The only registered filter is a `ShallowEtagHeaderFilter` for ETag support.

**Why the `Cache-Control: public, max-age=5` header is insufficient:** The response header instructs downstream proxies/CDNs to cache for 5 seconds, but: (a) this is not enforced at the application layer; (b) an attacker rotating through distinct valid topic IDs (e.g., `0.0.1`, `0.0.2`, … `0.0.N`) bypasses any proxy cache entirely, generating a fresh set of 3 DB queries per unique ID per request; (c) direct requests to the origin bypass CDN caching entirely.

### Impact Explanation
At 1,000 requests/second (trivially achievable from a single host with HTTP/1.1 keep-alive or HTTP/2), the attacker drives 3,000 DB queries/second against the shared PostgreSQL instance. The documented default DB connection pool maximum is 10 connections (`hiero.mirror.restJava.db`), meaning the pool saturates rapidly. This causes query queuing, connection timeout errors (`statementTimeout: 10000ms`), and cascading 503/504 failures for all legitimate users sharing the same database. The impact is service-wide degradation of the mirror node REST Java API with no economic cost to the attacker.

### Likelihood Explanation
Preconditions: none. The attacker needs only network access to the public endpoint. No credentials, no tokens, no on-chain activity required. The attack is trivially scriptable (`while true; do curl /api/v1/topics/0.0.$((RANDOM)); done`), repeatable indefinitely, and requires no specialized knowledge beyond the public OpenAPI spec. The 3× amplification ratio is modest but the absence of any application-level rate limiting makes sustained high-volume abuse straightforward.

### Recommendation
1. **Add rate limiting to rest-java**: Implement a `bucket4j`-based `OncePerRequestFilter` (mirroring the pattern in `web3/ThrottleConfiguration`) scoped to the `rest-java` module, enforcing a per-IP or global requests-per-second ceiling on `/api/v1/**` endpoints.
2. **Add application-level caching**: Annotate `TopicServiceImpl.findById()`, `EntityServiceImpl.findById()`, and `CustomFeeServiceImpl.findById()` with `@Cacheable` using a short TTL (e.g., 5s, matching the existing `Cache-Control` header) to collapse repeated queries for the same ID within the cache window.
3. **Enforce connection pool limits with circuit breaking**: Configure HikariCP `maximumPoolSize` with a connection acquisition timeout and expose a circuit breaker so DB saturation returns 503 quickly rather than queuing indefinitely.

### Proof of Concept
```bash
# Rotate through distinct topic IDs to bypass any proxy cache
# Each request triggers 3 DB queries in TopicController.getTopic()
for i in $(seq 1 10000); do
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/topics/0.0.$i" &
done
wait
# Result: up to 30,000 DB queries issued; connection pool exhausted;
# legitimate requests begin timing out or receiving 503 errors.
```