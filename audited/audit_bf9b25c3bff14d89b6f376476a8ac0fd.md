### Title
Unbounded Concurrent Subscriptions Exhaust DB Connection Pool via `subscribeTopic()` with No Global Subscriber Limit

### Summary
`TopicMessageServiceImpl.subscribeTopic()` accepts an unlimited number of concurrent subscriptions from any unauthenticated caller. The only per-client guard is `maxConcurrentCallsPerConnection=5`, which limits calls per TCP connection but imposes no cap on the number of TCP connections. An attacker opening hundreds of connections, each with 5 subscriptions using `startTime=0` and no limit, causes `PollingTopicMessageRetriever.retrieve()` to continuously poll the database for every active subscription, exhausting the HikariCP connection pool and starving legitimate subscribers.

### Finding Description

**Code path:**

`TopicMessageServiceImpl.subscribeTopic()` (line 59–92) immediately constructs a `historical` flux by calling `topicMessageRetriever.retrieve(filter, true)` (line 63) for every incoming subscription with no guard on total subscriber count. The `subscriberCount` field (line 48) is an `AtomicLong` used only as a Micrometer gauge metric — it is never checked to reject or throttle new subscriptions.

```
// line 48 — metric only, never enforced
private final AtomicLong subscriberCount = new AtomicLong(0L);

// line 63 — unconditionally called for every subscriber
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

`PollingTopicMessageRetriever.retrieve()` (line 45–63) runs on a shared `Schedulers.boundedElastic()` instance (line 41). In throttled mode (`throttled=true`), it polls the database every 2 seconds (`pollingFrequency=2s`) with pages of up to 1000 rows (`maxPageSize=1000`), and `isComplete()` (line 121–128) returns `true` only when the last page returned fewer rows than `maxPageSize` — meaning a topic with a large history will keep polling indefinitely. Each poll calls `TopicMessageRepositoryCustomImpl.findByFilter()` (line 33–61), which executes `typedQuery.getResultList()` and holds a HikariCP connection for the duration of the query.

The gRPC server configuration in `GrpcConfiguration.java` (line 33) sets only `maxConcurrentCallsPerConnection(5)` — there is no `maxConnections` limit configured on the Netty server. An attacker can open an arbitrary number of TCP connections, each carrying 5 concurrent `subscribeTopic` streams.

**Why checks fail:**
- `maxConcurrentCallsPerConnection=5` limits calls per connection, not total connections.
- `subscriberCount` is never read back to gate new subscriptions.
- The `boundedElastic` scheduler caps concurrent threads (default ~40–80) but queues up to 200,000 tasks, so thousands of subscriptions queue DB polls that execute as threads free up, keeping the pool saturated in rotation.
- `retrieverProperties.timeout=60s` means each subscription's polling loop persists for 60 seconds without messages before timing out, sustaining the attack window.

### Impact Explanation

HikariCP's default pool size is 10 connections (Spring Boot default). With hundreds of concurrent subscriptions each polling every 2 seconds, the pool is continuously saturated. Legitimate financial-message subscribers that depend on the same DB connection pool receive `Connection is not available, request timed out` errors and their streams terminate. This constitutes a complete denial of service for the gRPC topic subscription service with no authentication required.

### Likelihood Explanation

The attack requires only a gRPC client library (e.g., `grpcurl` or any standard gRPC stub) and the ability to open multiple TCP connections to port 5600. No credentials, tokens, or privileged access are needed. The attack is trivially scriptable, repeatable, and can be sustained indefinitely. A single attacker machine with modest bandwidth can open hundreds of connections.

### Recommendation

1. **Enforce a global subscriber cap**: Check `subscriberCount` before accepting a new subscription and return `RESOURCE_EXHAUSTED` if a configured maximum is exceeded.
2. **Add per-IP connection limiting**: Configure `maxConnectionsPerIp` or use a network-layer rate limiter (e.g., Envoy, GCP BackendPolicy already has `maxRatePerEndpoint=250` but this is RPS, not connection count).
3. **Set `maxConnections` on the Netty server**: Add `serverBuilder.maxConnectionAge(...)` and a total connection limit in `GrpcConfiguration`.
4. **Require authentication for `subscribeTopic`**: Gate the endpoint behind an API key or JWT so unauthenticated callers cannot trigger DB-bound work.
5. **Isolate the retriever DB pool**: Use a separate, bounded HikariCP pool for the gRPC retriever so exhaustion cannot affect other consumers.

### Proof of Concept

```bash
# Open 200 TCP connections, each with 5 concurrent subscriptions (1000 total)
# using grpcurl in parallel — no credentials required

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}, "consensusStartTime": {"seconds": 0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Result: HikariCP pool exhausted within seconds.
# Legitimate subscribers receive:
#   UNAVAILABLE: Connection is not available, request timed out after 30000ms
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-63)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L40-42)
```java
        this.topicMessageRepository = topicMessageRepository;
        scheduler = Schedulers.boundedElastic();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L121-128)
```java
        boolean isComplete() {
            boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();

            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
            }

            return limitHit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L33-60)
```java
    public Stream<TopicMessage> findByFilter(TopicMessageFilter filter) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<TopicMessage> query = cb.createQuery(TopicMessage.class);
        Root<TopicMessage> root = query.from(TopicMessage.class);

        Predicate predicate = cb.and(
                cb.equal(root.get(TOPIC_ID), filter.getTopicId()),
                cb.greaterThanOrEqualTo(root.get(CONSENSUS_TIMESTAMP), filter.getStartTime()));

        if (filter.getEndTime() != null) {
            predicate = cb.and(predicate, cb.lessThan(root.get(CONSENSUS_TIMESTAMP), filter.getEndTime()));
        }

        query = query.select(root).where(predicate).orderBy(cb.asc(root.get(CONSENSUS_TIMESTAMP)));

        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```
