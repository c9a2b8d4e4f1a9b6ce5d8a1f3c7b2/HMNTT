### Title
Unauthenticated Unbounded Historical Topic Message Stream via ConsensusTopicQuery (startTime=0, no limit, no endTime)

### Summary
The gRPC `subscribeTopic` endpoint in `ConsensusController` accepts a `ConsensusTopicQuery` from any unauthenticated caller. When `consensusStartTime` is set to epoch (seconds=0), no `consensusEndTime` is provided, and `limit` is omitted (defaults to 0), the service streams the entire historical message database for the requested topic indefinitely. No authentication, authorization, or server-side result-count cap exists on this endpoint.

### Finding Description

**Code path:**

`ConsensusController.toFilter()` ( [1](#0-0) ) converts the incoming protobuf query into a `TopicMessageFilter`. When the client sets `consensusStartTime = {seconds: 0}`, `query.hasConsensusStartTime()` returns `true` (Timestamp is a proto3 message field with presence tracking), and `convertTimestamp` returns `0L`. The filter is built with `startTime=0`, `endTime=null`, `limit=0`.

**Validation bypass:**

`TopicMessageFilter.isValidStartTime()` only checks `startTime <= DomainUtils.now()`. [2](#0-1)  Since `0` is always less than the current nanosecond timestamp, this constraint passes unconditionally for epoch input.

`TopicMessageFilter.hasLimit()` returns `limit > 0`. [3](#0-2)  With `limit=0` (the proto3 default when the field is omitted), `hasLimit()` is `false`.

**No cap applied in service layer:**

In `TopicMessageServiceImpl.subscribeTopic()`, the `takeWhile` guard is skipped when `endTime == null`, and the `take(limit)` guard is skipped when `!filter.hasLimit()`. [4](#0-3)  The retriever then sets `limit = Integer.MAX_VALUE` and pages through every row in the database for that topic, emitting them all to the subscriber.

**No authentication or rate limiting on the gRPC layer:**

The only registered `ServerInterceptor` is `GrpcInterceptor`, which solely sets an `EndpointContext` for table-usage tracking and unconditionally calls `next.startCall`. [5](#0-4)  There is no authentication check, no per-IP rate limit, and no per-subscriber message-count cap on the gRPC service. The throttle/rate-limit infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module and is not wired into the `grpc` module. [6](#0-5) 

`NettyProperties.maxConcurrentCallsPerConnection = 5` limits calls per TCP connection but does not prevent an attacker from opening many connections. [7](#0-6) 

### Impact Explanation
Any internet-accessible deployment exposes the full historical message corpus of any topic to unauthenticated callers. A single long-lived subscription with `startTime=0` and no limit causes the server to page through and transmit every stored `TopicMessage` row for that topic. Multiple concurrent such subscriptions exhaust database connections, network bandwidth, and reactive scheduler threads (`boundedElastic`), causing denial of service for legitimate subscribers. Topic messages may contain application-layer sensitive data (e.g., private business records submitted to HCS).

### Likelihood Explanation
The exploit requires only a valid `topicID` (topic IDs are public and enumerable from the REST API) and a standard gRPC client. No credentials, tokens, or special network position are needed. The attack is trivially scriptable, repeatable, and can be parallelized across many connections. The protobuf schema explicitly documents that omitting `limit` causes indefinite streaming, making the behavior predictable to any attacker who reads the proto file. [8](#0-7) 

### Recommendation
1. **Enforce a server-side maximum on historical retrieval**: In `TopicMessageServiceImpl.subscribeTopic()`, when `!filter.hasLimit()`, apply a configurable server-side cap (e.g., `flux.take(grpcProperties.getMaxHistoricalMessages())`).
2. **Reject or clamp unreasonably old `startTime`**: Reject queries where `startTime` is older than a configurable retention window (e.g., 30 days), or default `startTime` to `now()` when the field is not explicitly set.
3. **Add per-connection/per-IP rate limiting and concurrent-subscription limits** in the gRPC layer, analogous to the `ThrottleConfiguration` in the `web3` module.
4. **Require authentication** for `subscribeTopic` calls, or at minimum enforce stricter anonymous-caller limits.

### Proof of Concept
```python
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto.services import basic_types_pb2, timestamp_pb2

channel = grpc.insecure_channel("mirror-node-grpc-host:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1234),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    # no consensusEndTime, no limit
)

# Streams entire historical DB for topic 1234 with no authentication
for response in stub.subscribeTopic(query):
    print(response.sequenceNumber, response.message)
```

Preconditions: network access to the gRPC port (default 5600), any valid `topicNum`. No credentials required. The stream will not terminate until the client disconnects or the server crashes.

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

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L16-22)
```java
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L23-26)
```text
    // The maximum number of messages to receive before stopping. If not set or set to zero it will return messages
    // indefinitely.
    uint64 limit = 4;
}
```
