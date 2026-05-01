### Title
Unbounded Subscription Accumulation via Missing Global Subscriber Limit Enables Memory Exhaustion DoS

### Summary
When a client subscribes to a topic without setting `endTime`, `TopicMessageServiceImpl.pastEndTime()` unconditionally returns `Flux.never()`, and `TopicContext.isComplete()` unconditionally returns `false`. This means each such subscription's reactive pipeline has no server-side termination condition and lives indefinitely. Because there is no global cap on total concurrent subscriptions — only a per-connection limit of 5 — an attacker opening many connections accumulates unbounded JVM state, leading to slow memory exhaustion.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.pastEndTime()` at lines 123–131: [1](#0-0) 

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();   // ← no termination signal ever emitted
    }
    ...
}
```

This return value is used as the termination signal in `subscribeTopic()` at line 73: [2](#0-1) 

```java
Flux<TopicMessage> flux = historical
    .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
```

`takeUntilOther(Flux.never())` means the live stream never terminates from the server side.

`TopicContext.isComplete()` at lines 203–215 also returns `false` unconditionally when `endTime == null`: [3](#0-2) 

Each subscription allocates a `TopicContext` (holding `AtomicLong`, `AtomicReference<TopicMessage>`, `Stopwatch`, `EntityId`) plus the full Reactor operator chain and a live listener subscription (Redis or polling).

**Root cause:** The design intentionally supports open-ended subscriptions, but there is no server-enforced upper bound on how many can coexist simultaneously.

**Existing check reviewed — insufficient:**

`GrpcConfiguration.java` line 33 sets `maxConcurrentCallsPerConnection = 5`: [4](#0-3) 

This limits concurrent gRPC streams *per TCP connection*, not globally. An attacker opens N TCP connections × 5 streams each = 5N indefinitely-live subscriptions. No global connection count limit, no per-IP subscription cap, and no `maxConnectionAge`/`maxConnectionIdle` is configured anywhere in the application.

The GCP gateway `maxRatePerEndpoint: 250` is a *rate* limit (new requests/second), not a concurrent-connection cap: [5](#0-4) 

The nginx proxy `grpc_read_timeout 600s` resets on every received message, so an active topic subscription continuously resets it: [6](#0-5) 

### Impact Explanation
Each open-ended subscription keeps a `TopicContext`, a Reactor pipeline, and a listener subscription alive in the JVM heap indefinitely. With no global subscriber ceiling, an attacker can accumulate thousands of live subscriptions across many connections, exhausting heap memory and causing OOM errors or severe GC pressure that degrades service for all legitimate users. The existing `GrpcHighMemory` alert fires only after memory exceeds 80%, by which point the service may already be impaired. [7](#0-6) 

### Likelihood Explanation
No authentication is required to call `subscribeTopic`. The gRPC endpoint is publicly reachable on port 5600. The attacker needs only a standard gRPC client (e.g., `grpcurl` or any HCS SDK), a valid topic ID (publicly discoverable on-chain), and the ability to open many TCP connections. The attack is repeatable, requires no special knowledge, and can be sustained from a single machine or a small botnet. The per-connection limit of 5 means the attacker needs ~200 connections to hold 1,000 live subscriptions — trivially achievable.

### Recommendation
1. **Enforce a global maximum subscriber count**: reject new subscriptions when `subscriberCount` exceeds a configurable threshold (e.g., 1,000).
2. **Enforce a maximum subscription duration for open-ended subscriptions**: if `endTime == null`, automatically terminate the subscription after a configurable wall-clock timeout (e.g., 1 hour), requiring clients to re-subscribe.
3. **Add per-IP connection limits** at the Netty or gateway layer (e.g., `maxConnectionsPerIp`).
4. **Configure `maxConnectionAge` and `maxConnectionIdle`** on the `NettyServerBuilder` to reclaim idle or long-lived connections.

### Proof of Concept
```python
import grpc, threading
from hedera import ConsensusService_pb2_grpc, mirror_proto

def open_subscription(channel):
    stub = ConsensusService_pb2_grpc.ConsensusServiceStub(channel)
    req = mirror_proto.ConsensusTopicQuery()
    req.topicID.topicNum = 1234   # any valid topic
    # No consensusEndTime set → endTime == null on server
    for _ in stub.subscribeTopic(req):
        pass  # consume messages to keep stream alive

channels = []
threads = []
for i in range(500):                        # 500 connections
    ch = grpc.insecure_channel("mirror-node:5600")
    channels.append(ch)
    for _ in range(5):                      # 5 streams per connection = 2500 total
        t = threading.Thread(target=open_subscription, args=(ch,), daemon=True)
        t.start()
        threads.append(t)

# 2500 indefinitely-live subscriptions now accumulate JVM heap
# Monitor: watch JVM memory climb until OOM or GC thrashing
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L72-74)
```java
        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
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

**File:** charts/hedera-mirror-grpc/values.yaml (L69-72)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
```

**File:** charts/hedera-mirror-grpc/values.yaml (L244-254)
```yaml
  GrpcHighMemory:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} memory usage reached {{ $value | humanizePercentage }}"
      summary: "Mirror gRPC API memory usage exceeds 80%"
    enabled: true
    expr: sum(jvm_memory_used_bytes{application="grpc"}) by (namespace, pod) / sum(jvm_memory_max_bytes{application="grpc"}) by (namespace, pod) > 0.8
    for: 5m
    labels:
      severity: critical
      application: grpc
      area: resource
```

**File:** docker-compose.yml (L225-227)
```yaml
        # Setting 600s read timeout for topic subscription. When the client receives a message the timeout resets to 0.
        location = /com.hedera.mirror.api.proto.ConsensusService/subscribeTopic { grpc_read_timeout 600s; grpc_pass grpc://grpc_host; }
        location /com.hedera.mirror.api.proto. { grpc_pass grpc://grpc_host; }
```
