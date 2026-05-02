### Title
Zombie Subscriber Accumulation via Network Partition — Unbounded Resource Exhaustion with Misleading Gauge Metric

### Summary
`subscribeTopic()` increments `subscriberCount` in `doOnSubscribe` and decrements it in `doFinally`, but `doFinally` only fires on a Reactor terminal signal (`COMPLETE`, `ERROR`, or `CANCEL`). When a network partition silently hangs a TCP connection — and no gRPC keepalive is configured on the server — no terminal signal is ever emitted, so the counter is never decremented. An unprivileged attacker can open arbitrarily many subscriptions without an `endTime`, then silently drop the network path, leaving zombie streams that hold server resources indefinitely while the `Gauge` reports an inflated subscriber count that operators cannot distinguish from legitimate load.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 89–90:

```java
.doOnSubscribe(s -> subscriberCount.incrementAndGet())   // line 89
.doFinally(s -> subscriberCount.decrementAndGet())       // line 90
```

**Root cause — three compounding gaps:**

1. **No gRPC keepalive configured.** `GrpcConfiguration.grpcServerConfigurer()` (lines 31–34) only sets `executor` and `maxConcurrentCallsPerConnection`. No `keepAliveTime`, `keepAliveTimeout`, `maxConnectionIdle`, or `maxConnectionAge` is set on the `NettyServerBuilder`. Without these, the server never probes a silent client and never closes a dead TCP connection.

2. **No subscription-level timeout for indefinite streams.** `pastEndTime()` (lines 123–131) returns `Flux.never()` when `filter.getEndTime() == null` (line 125). For the common case of an open-ended live subscription, there is no timer that would emit a terminal signal and trigger `doFinally`.

3. **`doFinally` requires a terminal signal.** Reactor's `doFinally` fires only on `SignalType.COMPLETE`, `SignalType.ERROR`, or `SignalType.CANCEL`. A silently-hung TCP connection produces none of these; the Flux simply stalls. `subscriberCount` is never decremented.

**Why existing mitigations are insufficient:**

- `maxConcurrentCallsPerConnection = 5` limits calls *per connection*, not total connections. An attacker opens many connections, each carrying up to 5 subscriptions.
- `RetrieverProperties.timeout = 60s` applies only to the historical-retrieval phase, not to the live `topicListener.listen()` stream.
- The nginx `grpc_read_timeout 600s` (docker-compose.yml line 226) only applies when traffic flows through the nginx proxy; direct gRPC connections bypass it entirely.
- The safety-check `Mono.delay` (lines 67–70) only polls for missing messages; it does not terminate the subscription.

### Impact Explanation
Each zombie stream holds a Netty channel, a Reactor subscription chain, a Redis/DB listener slot (via `topicListener.listen()`), and a thread-pool slot. With no upper bound on total connections and no keepalive to reap dead ones, an attacker can exhaust file descriptors, thread-pool capacity, and Redis subscriber slots, causing legitimate subscribers to be rejected or starved. Simultaneously, the `hiero.mirror.grpc.subscribers` Gauge reports an inflated count that looks like high legitimate load, masking the exhaustion from operators who rely on that metric for capacity decisions.

### Likelihood Explanation
No authentication or authorization is required to call `subscribeTopic`. The attacker needs only a gRPC client and the ability to silently drop packets (e.g., a local firewall `DROP` rule, a cloud security-group change, or a NAT timeout). This is trivially reproducible from any network position, requires no special knowledge of the system internals, and can be scripted to open thousands of connections before partitioning them. The attack is repeatable and persistent until the server process is restarted.

### Recommendation
Apply all three fixes together:

1. **Configure gRPC server keepalive** in `GrpcConfiguration`:
   ```java
   serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);
   serverBuilder.keepAliveTimeout(10, TimeUnit.SECONDS);
   serverBuilder.maxConnectionIdle(5, TimeUnit.MINUTES);
   serverBuilder.maxConnectionAge(1, TimeUnit.HOURS);
   ```
2. **Add a subscription-level idle/max-duration timeout** in `subscribeTopic()` regardless of `endTime`, e.g. `.timeout(grpcProperties.getMaxSubscriptionDuration())`, so `doFinally` is guaranteed to fire.
3. **Enforce a global concurrent-subscription cap** (not just per-connection) using a `Semaphore` or a server-side interceptor that rejects new calls when `subscriberCount` exceeds a configured threshold.

### Proof of Concept
```python
# Requires: grpcio, protobuf, and the mirror-node proto stubs
# Step 1: open N subscriptions without endTime
import grpc, threading, subprocess

stubs = []
for i in range(500):
    ch = grpc.insecure_channel("mirror-node-host:5600")
    stub = ConsensusServiceStub(ch)
    req = ConsensusTopicQuery(topic_id=..., consensus_start_time=...)
    # Start streaming but never read — iterator held open in background thread
    threading.Thread(target=lambda s=stub,r=req: list(s.subscribeTopic(r)), daemon=True).start()
    stubs.append(ch)

# Step 2: partition the network (drop outbound packets to the server)
subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "5600", "-j", "DROP"])

# Step 3: observe — subscriberCount Gauge stays at 500+, server threads/FDs exhausted,
#          new legitimate subscriptions time out or are rejected.
# Metric endpoint: GET /actuator/prometheus | grep hiero_mirror_grpc_subscribers
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-14)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
