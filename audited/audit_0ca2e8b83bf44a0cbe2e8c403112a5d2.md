### Title
Unbounded Subscription Lifetime in `PollingTopicListener.listen()` Enables Resource Exhaustion During Network Partition

### Summary
`PollingTopicListener.listen()` creates a Reactor `Flux` that polls the database indefinitely using `RepeatSpec.times(Long.MAX_VALUE)` with no subscription-level timeout and no server-side gRPC connection eviction policy. When a network partition occurs (or a client stops acknowledging TCP segments), the server-side subscription remains alive until the OS TCP keepalive fires (~2 hours on Linux defaults), during which the polling loop continues consuming database connections and `boundedElastic` scheduler threads for every open subscription.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, `listen()`, lines 38–43:

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)   // ← infinite repeat
                .jitter(0.1)
                .withFixedDelay(interval)              // ← polls DB every 500ms
                .withScheduler(scheduler))
```

There is no `.timeout(...)`, no `.take(Duration)`, and no `.takeUntil(...)` applied to this `Flux`.

**Root cause — failed assumptions:**

1. The design assumes the gRPC transport layer will promptly cancel the Reactor subscription when the client disconnects. This is true for a clean disconnect (FIN/RST), but **not** for a network partition where packets are silently dropped.
2. The design assumes an infrastructure layer (load balancer, proxy) will enforce a connection lifetime. The nginx config in `docker-compose.yml` line 226 sets `grpc_read_timeout 600s`, but this is only present in the Docker Compose deployment and is absent from the Kubernetes/GCP gateway path (`charts/hedera-mirror-grpc/values.yaml`).
3. The Netty server builder in `GrpcConfiguration` (lines 28–35) configures **only** `executor` and `maxConcurrentCallsPerConnection`. No `maxConnectionAge`, `maxConnectionIdle`, `keepAliveTime`, or `keepAliveTimeout` is set, leaving all of these at Netty's defaults of `Long.MAX_VALUE` (effectively infinite).

**Exploit flow:**

An attacker opens `N` TCP connections to port 5600. On each connection, they issue up to 5 `subscribeTopic` gRPC calls (the `maxConcurrentCallsPerConnection` limit) with no `endTime` and no `limit` in the `TopicMessageFilter`. In `TopicMessageServiceImpl.subscribeTopic()` (lines 79–85), the absence of `endTime` causes `pastEndTime()` to return `Flux.never()` (line 125), and the absence of `limit` skips the `.take(filter.getLimit())` guard (line 84). The live path calls `topicListener.listen(newFilter)` which, in POLL mode, enters the infinite `RepeatSpec` loop.

The attacker then installs a firewall rule (`iptables -A OUTPUT -d <server_ip> -j DROP`) to simulate a one-sided partition: the TCP connection is not torn down (no FIN/RST reaches the server), so the server's Netty layer sees the connection as alive. The Reactor subscription is never cancelled. Each subscription continues calling `topicMessageRepository.findByFilter()` every 500ms, holding a HikariCP database connection for each poll cycle.

With `N` connections × 5 calls each, the attacker can exhaust the `boundedElastic` thread pool and the database connection pool. The `GrpcHighDBConnections` alert threshold is 75% utilization, but by the time it fires the damage is already done.

### Impact Explanation

- **Database connection exhaustion**: Each active `PollingContext` issues a `findByFilter` query every 500ms. With a default HikariCP pool of ~10 connections and a `boundedElastic` pool capped at `max(number_of_CPUs * 10, 10)` threads, a modest number of zombie subscriptions can saturate both pools, causing legitimate subscribers to time out.
- **Memory**: Each `PollingContext` holds an `AtomicLong`, an `AtomicReference<TopicMessage>`, and the full `TopicMessageFilter` object. At scale these accumulate.
- **Duration**: Without server-side keepalive, zombie subscriptions persist for the OS TCP keepalive interval (~7200 seconds on Linux by default), far exceeding any reasonable partition duration.
- **Severity**: High. The service is publicly accessible (no authentication on `subscribeTopic`), the resource consumed (DB connections) is a hard bottleneck, and the attack is repeatable.

### Likelihood Explanation

No authentication or authorization is required to call `subscribeTopic`. Any external user can open gRPC connections and issue subscriptions. Simulating a one-sided partition requires only a local firewall rule on the attacker's machine after the connection is established — no privileged network access to the server is needed. The attack is trivially scriptable and repeatable. The only partial mitigations (nginx `grpc_read_timeout 600s` and `maxConcurrentCallsPerConnection=5`) are either deployment-specific or per-connection rather than global, so they reduce but do not eliminate the attack surface.

### Recommendation

1. **Add a subscription-level timeout in `listen()`**: Apply `.timeout(maxSubscriptionDuration)` to the returned `Flux`, where `maxSubscriptionDuration` is a configurable property (e.g., default 1 hour). This ensures the Reactor subscription self-terminates regardless of transport state.

2. **Configure Netty server-side keepalive** in `GrpcConfiguration`:
   ```java
   serverBuilder.keepAliveTime(30, TimeUnit.SECONDS);
   serverBuilder.keepAliveTimeout(10, TimeUnit.SECONDS);
   serverBuilder.maxConnectionIdle(300, TimeUnit.SECONDS);
   serverBuilder.maxConnectionAge(3600, TimeUnit.SECONDS);
   ```
   This causes the server to send HTTP/2 PING frames and detect dead connections within ~40 seconds rather than ~2 hours.

3. **Add a global connection limit** (e.g., via a Netty `ChannelHandler` or an IP-based rate limiter) to bound the total number of concurrent subscriptions from a single source IP.

4. **Ensure the nginx `grpc_read_timeout` is present in all deployment paths**, including the Kubernetes/GCP gateway configuration.

### Proof of Concept

```bash
# 1. Install grpcurl
# 2. Open 10 parallel subscriptions with no endTime/limit, then drop return traffic

for i in $(seq 1 10); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 1}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# 3. After connections are established, drop ACKs back to server (simulates partition)
iptables -A OUTPUT -d <mirror-node-host> -p tcp --dport 5600 -j DROP

# 4. Monitor server DB connections — they will remain elevated for ~2 hours
# Expected: HikariCP active connections stay at max; new legitimate subscribers
# receive connection timeout errors from the pool.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L79-85)
```java
        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-130)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }

        return Flux.empty()
                .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                        .withFixedDelay(grpcProperties.getEndTimeInterval()));
```

**File:** docker-compose.yml (L225-227)
```yaml
        # Setting 600s read timeout for topic subscription. When the client receives a message the timeout resets to 0.
        location = /com.hedera.mirror.api.proto.ConsensusService/subscribeTopic { grpc_read_timeout 600s; grpc_pass grpc://grpc_host; }
        location /com.hedera.mirror.api.proto. { grpc_pass grpc://grpc_host; }
```
