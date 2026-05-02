All code claims have been verified against the actual repository. Here is the result:

---

Audit Report

## Title
Unbounded Zombie gRPC Stream Resource Exhaustion via Missing Keepalive and Timeout in `PollingTopicListener.listen()`

## Summary
When the gRPC service is configured to use the `POLL` listener type, `PollingTopicListener.listen()` constructs an infinite polling `Flux` with no `.timeout()` operator, and the Netty gRPC server is configured with no TCP keepalive probes. A network partition that silently drops packets (no TCP FIN/RST) leaves server-side streams alive indefinitely, each issuing a DB query every 500 ms. An unprivileged attacker can manufacture this condition using a local firewall drop rule, causing unbounded resource exhaustion invisible to the application layer.

## Finding Description

**`PollingTopicListener.listen()` — no timeout:**

`listen()` builds an infinite polling `Flux` using `RepeatSpec.times(Long.MAX_VALUE)` with a fixed 500 ms delay and no `.timeout()` operator anywhere in the method or its call chain through `TopicMessageServiceImpl.incomingMessages()` → `topicListener.listen(newFilter)`. [1](#0-0) 

By contrast, `PollingTopicMessageRetriever.retrieve()` (the historical path) explicitly applies `.timeout(retrieverProperties.getTimeout(), scheduler)` at line 59 — the live listener has no equivalent. [2](#0-1) 

**`GrpcConfiguration` — no keepalive configured:**

The `ServerBuilderCustomizer<NettyServerBuilder>` bean sets only `executor` and `maxConcurrentCallsPerConnection`. No `keepAliveTime`, `keepAliveTimeout`, or `permitKeepAliveWithoutCalls` is set. A full grep of all Java sources for `keepAlive`/`keepalive` returns zero matches, confirming no keepalive is configured anywhere in the application. [3](#0-2) 

**Cancel handler is insufficient:**

`ConsensusController.subscribeTopic()` registers `disposable::dispose` as the `OnCancelHandler` on the `ServerCallStreamObserver`. This fires only when the gRPC framework receives a proper stream cancellation signal, which requires the TCP layer to deliver a RST or FIN. In a half-open TCP state (network partition with packet drop), no such signal arrives, so `dispose()` is never called and `subscriberCount.decrementAndGet()` / `doFinally` never fire. [4](#0-3) [5](#0-4) 

**Default listener type is REDIS, but POLL is a documented supported option:**

`ListenerProperties` defaults to `ListenerType.REDIS`, but `POLL` and `SHARED_POLL` are explicitly enumerated as supported types. When an operator switches to `POLL`, the vulnerability is fully exposed. [6](#0-5) 

## Impact Explanation

Each zombie subscription holds a slot in the `boundedElastic` scheduler thread pool and issues a DB query every 500 ms for the lifetime of the half-open TCP connection (up to ~2 hours under default Linux TCP keepalive). With `maxConcurrentCallsPerConnection = 5` and no per-IP connection limit, an attacker opening N TCP connections can sustain 5N zombie polling loops. At scale this exhausts the DB connection pool, the scheduler thread pool, and server memory, degrading or denying service to legitimate subscribers. The `subscriberCount` Micrometer gauge will show inflated counts but no error signal, making the condition invisible to alert rules that watch for stream errors. [7](#0-6) 

## Likelihood Explanation

No privileges are required. The attacker needs only a valid topic ID (publicly discoverable via the REST API) and the ability to manipulate their own outbound firewall (e.g., `iptables -A OUTPUT -p tcp --dport 5600 -j DROP` after the TCP handshake completes). This is a standard technique for creating half-open connections. It is repeatable, scriptable, and requires no authentication. The condition is conditional on the operator having switched the listener type from the default `REDIS` to `POLL`, but this is a documented and supported configuration.

## Recommendation

1. **Add a `.timeout()` operator to `PollingTopicListener.listen()`**, analogous to the existing `.timeout(retrieverProperties.getTimeout(), scheduler)` in `PollingTopicMessageRetriever.retrieve()`. A configurable idle/absolute timeout (e.g., 10–30 minutes) should be applied to the live stream. [1](#0-0) 

2. **Configure gRPC keepalive probes** in `GrpcConfiguration` via `NettyServerBuilder`:
   ```java
   serverBuilder.keepAliveTime(60, TimeUnit.SECONDS);
   serverBuilder.keepAliveTimeout(20, TimeUnit.SECONDS);
   serverBuilder.permitKeepAliveWithoutCalls(true);
   ```
   This causes the Netty layer to detect half-open connections and terminate them at the transport level. [8](#0-7) 

3. **Add a per-IP or global connection rate limit** to prevent a single attacker from opening unbounded TCP connections.

## Proof of Concept

```bash
# 1. Subscribe to a topic via gRPC (e.g., using grpcurl or a custom client)
grpcurl -plaintext -d '{"topicID":{"topicNum":1}}' <host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &

# 2. Immediately after the TCP handshake and subscription completes,
#    drop outbound packets to simulate a network partition:
iptables -A OUTPUT -p tcp --dport 5600 -j DROP

# 3. The server-side stream is now a zombie: no FIN/RST is delivered,
#    disposable::dispose is never called, and the server polls the DB
#    every 500 ms indefinitely. Repeat N times to scale the attack.
```

The server-side `subscriberCount` gauge will increment for each zombie stream and never decrement, confirming the resource leak is invisible to error-based alerting.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-48)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Starting to poll every {}ms: {}", interval.toMillis(), filter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L59-59)
```java
                .timeout(retrieverProperties.getTimeout(), scheduler)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L50-52)
```java
        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L52-55)
```java
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L89-91)
```java
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L37-43)
```java
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```
