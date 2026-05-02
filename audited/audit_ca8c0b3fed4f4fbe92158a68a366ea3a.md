### Title
Unbounded Multi-Connection Subscriber Flood Exhausts Resources in `subscribeTopic()` gRPC Endpoint

### Summary
The `subscribeTopic()` endpoint in `ConsensusController` accepts unlimited persistent streaming subscriptions from unauthenticated callers. The only throttle — `maxConcurrentCallsPerConnection = 5` — is scoped per-connection, not globally, so an attacker opening many connections bypasses it entirely. Each subscription allocates a `TopicContext`, schedules work on the shared `boundedElastic` thread pool via `PollingTopicMessageRetriever` and the safety-check path, and holds a database connection during historical retrieval, enabling full resource exhaustion with no privilege required.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) immediately subscribes to a reactive pipeline with no authentication, no per-IP limit, and no global subscriber cap:

```java
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(topicMessageService::subscribeTopic)
        ...
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
``` [1](#0-0) 

`TopicMessageServiceImpl.subscribeTopic()` (lines 59–92) creates a `TopicContext` per subscriber and schedules work on `Schedulers.boundedElastic()` for the safety-check path:

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
``` [2](#0-1) 

`PollingTopicMessageRetriever` (line 41) and `PollingTopicListener` (line 31) each create their own `Schedulers.boundedElastic()` scheduler and schedule blocking DB queries on it per subscriber: [3](#0-2) [4](#0-3) 

`SharedTopicListener.listen()` calls `.publishOn(Schedulers.boundedElastic(), ...)` for every subscriber's dispatch pipeline: [5](#0-4) 

**The only throttle — `maxConcurrentCallsPerConnection = 5` — is per-connection, not global:** [6](#0-5) [7](#0-6) 

**`subscriberCount` is a metric gauge only — it enforces nothing:** [8](#0-7) 

**Root cause:** The system assumes a single client opens one connection with a few streams. There is no per-IP connection limit, no global concurrent-subscriber cap, and no authentication. An attacker opens `N` connections × 5 streams = `5N` concurrent persistent subscriptions. Each subscription:
1. Schedules blocking DB queries on `boundedElastic` (default cap: `10 × CPU_cores` threads, e.g. 40 on a 4-core host).
2. Holds a DB connection from the pool during historical retrieval.
3. Allocates heap for `TopicContext`, filter objects, and reactive pipeline state.

With thousands of subscriptions, the `boundedElastic` thread pool saturates (all threads blocked on DB), the DB connection pool exhausts, and the task queue (default 100,000) fills, causing `RejectedExecutionException` for all new work — including legitimate subscriber pipelines.

### Impact Explanation

When the `boundedElastic` pool and DB connection pool are exhausted, no new `subscribeTopic()` calls can be processed, existing subscriptions stall waiting for DB results, and the gRPC service becomes unresponsive. The mirror node can no longer relay consensus topic messages to any client. The `grpc_read_timeout 600s` in the nginx proxy config means attacker streams are kept alive for up to 10 minutes per connection without sending any data, maximizing resource hold time. [9](#0-8) 

### Likelihood Explanation

No credentials, tokens, or on-chain accounts are required. A single attacker machine can open hundreds of HTTP/2 connections (each is a TCP connection with multiplexed streams) to port 5600 or through the nginx proxy. The `limit: 0` default in the protobuf definition means each stream stays open indefinitely with no server-side timeout enforced at the application layer. The attack is trivially scriptable with `grpcurl` or any gRPC client library and is fully repeatable. [10](#0-9) 

### Recommendation

1. **Enforce a global concurrent-subscriber cap** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` status if exceeded.
2. **Add per-IP connection limiting** at the Netty layer via `ServerBuilderCustomizer` (e.g., using a `ChannelHandler` that tracks connections per remote address).
3. **Add a maximum subscription duration / idle timeout** at the application layer — terminate streams that have received no messages for a configurable period.
4. **Enforce authentication** (e.g., API key or JWT) before accepting streaming subscriptions.
5. **Expose `maxRatePerEndpoint`** enforcement at the infrastructure level for all deployment modes, not just GCP gateway. [11](#0-10) 

### Proof of Concept

```bash
# Open 200 connections × 5 streams = 1000 concurrent persistent subscriptions
# (no credentials needed, limit=0 means streams never self-terminate)

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observe: boundedElastic thread pool saturates, DB connection pool exhausts,
# new legitimate subscribeTopic() calls receive UNAVAILABLE or hang indefinitely.
# Monitor via: curl http://<host>:8081/actuator/metrics/hiero.mirror.grpc.subscribers
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-42)
```java
        scheduler = Schedulers.boundedElastic();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L24-25)
```java
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-34)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** docker-compose.yml (L226-226)
```yaml
        location = /com.hedera.mirror.api.proto.ConsensusService/subscribeTopic { grpc_read_timeout 600s; grpc_pass grpc://grpc_host; }
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L23-25)
```text
    // The maximum number of messages to receive before stopping. If not set or set to zero it will return messages
    // indefinitely.
    uint64 limit = 4;
```

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```
