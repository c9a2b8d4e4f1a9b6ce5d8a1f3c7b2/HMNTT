### Title
Unbounded Subscription Slot Exhaustion via Non-Existent Topics When `checkTopicExists=false`

### Summary
When `hiero.mirror.grpc.checkTopicExists` is set to `false`, `subscribeTopic()` accepts subscriptions to any arbitrary topic ID without verifying existence, creating a persistent `TopicContext` and holding a gRPC stream open indefinitely. The `subscriberCount` field is a metric-only gauge with no enforced ceiling, and the per-connection call limit (`maxConcurrentCallsPerConnection=5`) is the only throttle — it applies per TCP connection, not globally. An unauthenticated attacker opening many TCP connections can exhaust server-side resources (memory, Reactor scheduler threads, DB connection pool) with no application-layer rejection.

### Finding Description
**Exact code path:**

In `TopicMessageServiceImpl.java`, `subscribeTopic()` (lines 59–92): [1](#0-0) 

A `TopicContext` is unconditionally allocated at line 61 before any existence check. The existence check is deferred to `topicExists()` (lines 94–106): [2](#0-1) 

When `checkTopicExists=false`, the `switchIfEmpty` branch at lines 98–103 synthesizes a valid `Entity` with `EntityType.TOPIC` for any topic ID, bypassing the rejection path entirely. The subscription then proceeds to the full live-stream pipeline.

**Stream lifetime:** `pastEndTime()` (lines 123–131) returns `Flux.never()` when no `endTime` is supplied: [3](#0-2) 

Without `endTime` or `limit`, the stream never self-terminates. The `subscriberCount` at line 48 is a Micrometer `Gauge` — it is incremented/decremented for observability only and is never compared against a maximum to reject new subscriptions: [4](#0-3) 

**The only application-level throttle** is `maxConcurrentCallsPerConnection=5` in `NettyProperties`: [5](#0-4) 

This is applied per TCP connection in `GrpcConfiguration.java`: [6](#0-5) 

There is no `maxConnections`, `maxConnectionAge`, `maxConnectionIdle`, IP-rate-limit, or global subscriber cap configured anywhere in the gRPC server setup. No authentication is required to call `subscribeTopic`.

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection` bounds total server load. It does not — it only bounds streams per single TCP connection. An attacker controlling N connections can hold N×5 streams open simultaneously, and N is unbounded.

### Impact Explanation
Each open stream allocates a `TopicContext` (heap), a multi-stage Reactor `Flux` pipeline (including a `Mono.delay` on `Schedulers.boundedElastic()`), and a gRPC HTTP/2 stream slot. For a non-existent topic, the listener will poll or wait indefinitely, consuming a slot in the `boundedElastic` scheduler thread pool and potentially issuing repeated DB queries (via the safety-check path at lines 67–70). With enough connections the attacker can:

- Exhaust the `boundedElastic` thread pool, stalling all legitimate subscribers
- Exhaust the DB connection pool, causing query timeouts for all mirror-node components
- Exhaust JVM heap, triggering OOM

This constitutes a full denial-of-service against the gRPC service and potentially the shared database.

### Likelihood Explanation
The precondition (`checkTopicExists=false`) is a documented, operator-settable flag. The documentation explicitly lists it: [7](#0-6) 

Any operator who sets this flag (e.g., to support pre-registration topic subscriptions) exposes the endpoint. The attack requires no credentials, no knowledge of valid topic IDs, and only a standard gRPC client. Opening thousands of TCP connections from a single host or a small botnet is trivially achievable. The attack is repeatable and persistent until the server is restarted or connections are forcibly closed.

### Recommendation
1. **Enforce a global subscriber cap**: Check `subscriberCount` against a configurable maximum before proceeding in `subscribeTopic()`, and return `RESOURCE_EXHAUSTED` status if exceeded.
2. **Add `maxConnectionAge` / `maxConnectionIdle`** to `GrpcConfiguration` via `NettyServerBuilder` to recycle long-lived idle connections.
3. **Add a per-IP connection rate limit** at the proxy or application layer.
4. **Add a server-side stream idle timeout**: If no message is emitted within a configurable window (e.g., `retriever.timeout`), terminate the stream with an appropriate status rather than holding it open indefinitely.
5. **Treat `checkTopicExists=false` as a high-risk configuration** and document that it must only be used behind authenticated/rate-limited infrastructure.

### Proof of Concept
```python
import grpc
import threading
# proto: com.hedera.mirror.api.proto.ConsensusService/subscribeTopic

TARGET = "grpc-mirror-node:5600"
FAKE_TOPIC = (0, 0, 999999999)  # non-existent topic
NUM_CONNECTIONS = 200            # each holds 5 streams = 1000 total streams

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = ConsensusServiceStub(channel)
    streams = []
    for _ in range(5):  # maxConcurrentCallsPerConnection=5
        req = ConsensusTopicQuery(
            topicID=TopicID(shardNum=0, realmNum=0, topicNum=999999999),
            # no endTime, no limit → stream never terminates
        )
        streams.append(stub.subscribeTopic(req))
    # hold all streams open
    for s in streams:
        try:
            for _ in s:
                pass
        except:
            pass

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads:
    t.start()
# Result: 1000 persistent TopicContext objects + Reactor pipelines held open,
# boundedElastic thread pool saturated, DB connection pool exhausted,
# legitimate subscribers receive UNAVAILABLE or timeout.
```

**Preconditions:** `hiero.mirror.grpc.checkTopicExists=false` is set in the server configuration. No authentication or special privileges required.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-92)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });

        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }

        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-131)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }

        return Flux.empty()
                .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                        .withFixedDelay(grpcProperties.getEndTimeInterval()));
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

**File:** docs/configuration.md (L409-409)
```markdown
| `hiero.mirror.grpc.checkTopicExists`                       | true             | Whether to throw an error when the topic doesn't exist                                                    |
```
