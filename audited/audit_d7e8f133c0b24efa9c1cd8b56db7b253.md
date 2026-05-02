### Title
Unbounded Permanent gRPC Topic Subscription with No Authentication or Rate Limiting Enables Resource Exhaustion and Unrestricted Data Harvesting

### Summary
The `subscribeTopic()` method in `TopicMessageServiceImpl` accepts a `TopicMessageFilter` with `startTime=0`, no `endTime`, and no `limit` from any unauthenticated caller. The only gate is topic existence. This allows any external user to open a permanent, unbounded subscription that streams the entire historical and live message feed for any topic, with no throttling, no connection cap, and no authentication — enabling both unrestricted data harvesting and resource exhaustion (DoS) via subscription flooding.

### Finding Description

**Code path and root cause:**

In `TopicMessageFilter.java`, `startTime` is annotated `@Min(0)` and validated by `isValidStartTime()` which only checks `startTime <= DomainUtils.now()`. Since `DomainUtils.now()` returns nanoseconds since epoch, `startTime=0` always passes. [1](#0-0) 

`endTime` is nullable with no requirement to be set, and `limit` defaults to `0` with `hasLimit()` returning `false` when `limit == 0`. [2](#0-1) 

In `subscribeTopic()`, the `endTime` and `limit` guards are both conditional — if absent, no termination condition is applied to the flux: [3](#0-2) 

The `pastEndTime()` helper returns `Flux.never()` when `endTime` is null, meaning the live subscription leg never terminates: [4](#0-3) 

`isComplete()` in `TopicContext` returns `false` unconditionally when `endTime` is null: [5](#0-4) 

The only access control is `topicExists()`, which merely checks that the entity exists and has type `TOPIC`. There is no authentication, no authorization, no per-client connection limit, and no rate limiting: [6](#0-5) 

The sole gRPC server interceptor in the codebase only sets an endpoint context for metrics — it performs no authentication or authorization: [7](#0-6) 

The `subscriberCount` is tracked as a metric but is never enforced as a cap: [8](#0-7) 

**Exploit flow:**

1. Attacker discovers any valid topic ID (trivially enumerable from the public ledger or mirror REST API).
2. Attacker sends a gRPC `subscribeTopic` request with `topicId=<target>`, `startTime=0`, no `endTime`, no `limit`.
3. `topicExists()` passes (topic exists).
4. `topicMessageRetriever.retrieve(filter, true)` begins streaming all historical messages from nanosecond 0.
5. After historical replay, `incomingMessages()` attaches to the live listener indefinitely.
6. The subscription never terminates — `pastEndTime()` returns `Flux.never()`, `isComplete()` always returns `false`, no `takeWhile` or `take` is applied.
7. Attacker repeats this from multiple connections/IPs; each subscription holds a DB cursor and reactive pipeline open indefinitely.

### Impact Explanation

**Resource exhaustion (DoS):** Each permanent subscription holds open a database retrieval cursor, a reactive Flux pipeline, and a gRPC stream. With no per-client or global subscription cap enforced, an attacker can open thousands of such subscriptions, exhausting database connection pools, heap memory, and thread scheduler capacity, degrading or crashing the service for all legitimate users.

**Unrestricted data harvesting:** All topic message content — including any sensitive application-layer data encoded in HCS messages — is streamed in full to any caller. While HCS is nominally public, operators frequently use topics for application-specific messaging (e.g., audit logs, NFT metadata, supply chain events) with an implicit expectation that bulk historical replay requires some form of access control or rate limiting.

Severity: **High** (DoS vector is fully unauthenticated and trivially repeatable; data harvesting is complete and unbounded).

### Likelihood Explanation

Preconditions are minimal: network access to the gRPC port and knowledge of any topic ID (both trivially satisfied). No credentials, tokens, or special privileges are required. The attack is fully scriptable, repeatable from any IP, and requires no prior knowledge of the system internals beyond the public protobuf API definition. Any motivated attacker or automated scanner can trigger this.

### Recommendation

1. **Enforce a maximum subscription duration**: Require `endTime` to be set, or impose a server-side maximum TTL (e.g., configurable via `GrpcProperties`) after which the subscription is forcibly terminated.
2. **Enforce a minimum `startTime`**: Reject `startTime` values older than a configurable retention window (e.g., 7 days) to prevent full historical replay by unauthenticated callers.
3. **Enforce per-client and global subscription limits**: Track active subscriptions per remote peer and reject new subscriptions beyond a threshold. Enforce a global cap via `subscriberCount`.
4. **Add authentication/authorization**: Introduce a gRPC `ServerInterceptor` that validates caller identity (API key, JWT, mTLS) before allowing subscription.
5. **Add rate limiting**: Throttle subscription creation per IP/client using a token bucket or similar mechanism at the interceptor layer.

### Proof of Concept

```python
# Requires: grpcio, hedera mirror node proto stubs
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from com.hederahashgraph.api.proto.java import basic_types_pb2

channel = grpc.insecure_channel("mirror-node-grpc-host:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

# Craft filter: startTime=0 (epoch), no endTime, no limit
request = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1234),
    consensusStartTime=basic_types_pb2.Timestamp(seconds=0, nanos=0),
    # consensusEndTime omitted
    # limit omitted (defaults to 0 = unlimited)
)

# Open permanent subscription — streams ALL historical + future messages
for msg in stub.subscribeTopic(request):
    print(msg)  # Runs forever, no server-side termination

# To DoS: open N concurrent connections
import threading
for _ in range(1000):
    threading.Thread(target=lambda: list(stub.subscribeTopic(request))).start()
```

No credentials required. Repeatable from any network-accessible client.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-51)
```java
    private Long endTime;

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

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L79-85)
```java
        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
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

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-22)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```
