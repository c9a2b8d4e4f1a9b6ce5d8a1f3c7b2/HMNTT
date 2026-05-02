### Title
Cache Miss on Negative Lookups Enables DB Connection Pool Exhaustion via Unauthenticated `subscribeTopic()` Flood

### Summary
The `topicExists()` method in `TopicMessageServiceImpl` performs a synchronous blocking JDBC call (`entityRepository.findById()`) on every `subscribeTopic()` invocation for non-existent topic IDs, because the `@Cacheable` annotation is configured with `unless = "#result == null"`, preventing negative-lookup caching. With no rate limiting on the gRPC endpoint and no limit on the number of client connections, an unauthenticated attacker can flood the service with requests for non-existent topics, exhausting the HikariCP connection pool and denying service to all legitimate users.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `topicExists()`, lines 94–106:

```java
private Mono<?> topicExists(TopicMessageFilter filter) {
    var topicId = filter.getTopicId();
    return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))  // line 96 — blocking JDBC call
            .switchIfEmpty(
                    grpcProperties.isCheckTopicExists()
                            ? Mono.error(new EntityNotFoundException(topicId))
                            ...
```

`grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java`, line 14–15:

```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
Optional<Entity> findById(long entityId);
```

**Root cause:** The `unless = "#result == null"` condition on `@Cacheable` means that when `findById` returns `Optional.empty()` (entity not found), the result is **not stored in the cache**. Every subsequent request for the same non-existent topic ID re-executes the blocking JDBC query and acquires a connection from the HikariCP pool.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` (in `NettyProperties`) limits concurrency *per connection*, but there is no cap on the number of simultaneous gRPC connections from a single client or globally.
- No rate limiting exists in the `grpc` module. The `ThrottleConfiguration`/`ThrottleManagerImpl` with Bucket4j is exclusively in the `web3` module and is never applied to gRPC endpoints.
- The blocking `entityRepository.findById()` call is not wrapped in `subscribeOn(Schedulers.boundedElastic())`, meaning it executes on the gRPC executor thread pool, blocking those threads during the DB round-trip.
- HikariCP's default maximum pool size is 10 connections. With enough concurrent requests, the pool queue fills and new requests time out.

### Impact Explanation
A successful attack exhausts the shared HikariCP connection pool. Once the pool is saturated, all database-dependent operations across the gRPC service stall — including legitimate topic subscriptions, historical message retrieval, and address book queries. This constitutes a full denial-of-service against the mirror node's gRPC API with no authentication required. Severity: **High** (unauthenticated, full service disruption).

### Likelihood Explanation
The attack requires only a gRPC client (e.g., `grpcurl`) and knowledge of the public `subscribeTopic` RPC. No credentials, tokens, or special privileges are needed. The attacker simply opens many TCP connections and sends concurrent `subscribeTopic` requests with arbitrary non-existent topic IDs (e.g., `topicNum: 999999999`). This is trivially scriptable and repeatable. The absence of any connection-level or request-level rate limiting on the gRPC service makes sustained exploitation straightforward.

### Recommendation
1. **Cache negative lookups**: Change the `@Cacheable` condition to also cache empty results, e.g., cache a sentinel value for missing entities, or use a separate negative-result cache. Remove `unless = "#result == null"` or replace with a bounded negative cache.
2. **Add rate limiting to the gRPC layer**: Apply a per-IP or global request rate limiter (e.g., gRPC server interceptor using Bucket4j, similar to the `web3` module) to `subscribeTopic`.
3. **Wrap the blocking call**: Move `entityRepository.findById()` onto `Schedulers.boundedElastic()` to avoid blocking gRPC executor threads: `Mono.fromCallable(() -> entityRepository.findById(topicId.getId())).subscribeOn(Schedulers.boundedElastic())`.
4. **Limit total gRPC connections**: Configure `NettyServerBuilder.maxConnectionAge` and a global connection limit to bound the total number of concurrent clients.

### Proof of Concept
```bash
# Open 20 parallel gRPC streams, each requesting a non-existent topic
# Repeat in a tight loop to saturate the HikariCP pool (default: 10 connections)

for i in $(seq 1 20); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 999999999}}' \
    localhost:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait

# Expected result:
# - DB connection pool exhausted (HikariCP timeout errors in server logs)
# - Legitimate subscribeTopic calls begin timing out or returning RESOURCE_EXHAUSTED
# - All DB-backed gRPC operations degrade until attacker stops
```

Each iteration of the loop bypasses the entity cache (null not cached per `unless = "#result == null"`), executes a blocking `SELECT` against the `entity` table, and holds a pool connection for the query duration. With 20+ concurrent streams and a pool size of 10, the pool is exhausted.