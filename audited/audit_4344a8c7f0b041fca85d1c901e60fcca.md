### Title
Unbounded Concurrent Subscriptions in `subscribeTopic()` Enable CPU Exhaustion via `toResponse()` Fan-Out

### Summary
The `subscribeTopic()` endpoint in `ConsensusController` accepts unlimited concurrent subscriptions from unauthenticated callers with no global subscriber cap, no per-IP connection limit, and no enforcement of a message limit or end time. When a high-volume topic is targeted, the `toResponse()` conversion is executed independently for every message for every active subscriber, multiplying CPU consumption linearly with subscriber count and enabling a single attacker to exhaust server CPU.

### Finding Description
**Exact code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) accepts any `ConsensusTopicQuery` with no authentication, no per-caller quota, and no global subscriber ceiling:

```java
public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(topicMessageService::subscribeTopic)
            .map(this::toResponse)   // ← called per-message, per-subscriber, no caching
            ...
``` [1](#0-0) 

The `toResponse()` method (lines 84–116) performs full protobuf object construction, byte-array wrapping, and conditional `TransactionID.parseFrom()` deserialization for every message delivered to every subscriber. The developer comment at line 83 explicitly acknowledges the fan-out cost: *"Consider caching this conversion for multiple subscribers to the same topic if the need arises."* [2](#0-1) 

**Root cause — failed assumptions:**

1. `TopicMessageServiceImpl` tracks `subscriberCount` only as a Micrometer gauge metric; it is never compared against any ceiling and never rejects new subscriptions: [3](#0-2) 

2. When a client sends `limit=0` and omits `consensusEndTime`, `pastEndTime()` returns `Flux.never()` (subscription lives forever) and no `take()` is applied: [4](#0-3) 

3. The only server-side guard is `maxConcurrentCallsPerConnection = 5`, which is a **per-TCP-connection** limit, not a global or per-IP limit. An attacker opens N independent TCP connections, each carrying 5 subscriptions, yielding N×5 unbounded live subscriptions: [5](#0-4) [6](#0-5) 

4. No rate-limiting exists in the gRPC module. The `ThrottleConfiguration`/`ThrottleManagerImpl` classes are confined to the `web3` module and are not applied here.

### Impact Explanation
For a high-volume HCS topic (e.g., a topic receiving hundreds of messages per second on mainnet), each new message triggers `toResponse()` once per active subscriber. With N×5 subscriptions open, CPU consumption scales as O(N × message_rate). At sufficient N, the JVM thread pool and reactive scheduler become saturated, causing the mirror node's gRPC service to stop responding to all clients — including legitimate ones — constituting a complete denial of service of the consensus subscription API. Because the mirror node is a critical read path for applications relying on HCS, this directly impacts the availability of the Hedera ecosystem's data layer.

### Likelihood Explanation
The attack requires no credentials, no on-chain funds, and no special knowledge beyond a valid topic ID (all topic IDs are publicly enumerable via the REST API). Opening thousands of TCP connections is trivially achievable from a single host or a small botnet. The attacker sustains the attack indefinitely at near-zero cost because each subscription is a long-lived streaming RPC that the server keeps alive. The attack is fully repeatable and requires no coordination.

### Recommendation
1. **Enforce a global (or per-IP) subscriber ceiling** inside `TopicMessageServiceImpl.subscribeTopic()`: compare `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` when exceeded.
2. **Enforce a per-IP concurrent-subscription limit** at the Netty layer (e.g., via a gRPC `ServerInterceptor` that tracks active calls per remote address).
3. **Cache `toResponse()` output** per `(topicId, sequenceNumber)` for a short TTL so that N subscribers to the same topic share a single serialization, eliminating the linear CPU fan-out.
4. **Require a non-zero `limit` or a finite `endTime`** for subscriptions, or impose a server-side maximum subscription duration, to prevent indefinitely-lived streams.
5. **Apply the existing `bucket4j` rate-limiting pattern** (already used in the `web3` module) to the gRPC service to cap new subscription establishment rate per IP.

### Proof of Concept
```bash
# Open 200 TCP connections, each with 5 subscriptions = 1000 concurrent live subscriptions
# targeting a high-volume topic (e.g., topicNum 1234 on mainnet)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1234}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
# No limit=, no consensusEndTime= → each subscription lives forever
# Each new message on topic 1234 triggers toResponse() 1000 times simultaneously
# Monitor CPU: watch -n1 'ps aux | grep java'
# Legitimate subscribers will begin timing out as the executor saturates
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```
