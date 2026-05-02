### Title
Unbounded Concurrent gRPC Subscriptions Enable Resource Exhaustion via Missing Global Connection and Subscription Limits

### Summary
The `TopicListener.listen()` interface and all its implementations impose no global cap on concurrent subscriptions or TCP connections. The only guard, `maxConcurrentCallsPerConnection = 5`, is scoped per-connection, so an attacker opening many connections can create an unbounded number of concurrent streaming subscriptions. Each subscription in `POLL` mode independently queries the database, and every subscription in every mode allocates a 16,384-message backpressure buffer, leading to database connection pool exhaustion and heap exhaustion that renders the gRPC node unresponsive.

### Finding Description

**Code path:**

`TopicListener.listen()` is the interface entry point. [1](#0-0) 

`CompositeTopicListener.listen()` delegates to the configured implementation with no subscriber count check or rate gate: [2](#0-1) 

`PollingTopicListener.listen()` creates a brand-new, independent `PollingContext` and a new polling `Flux` for every call — one DB query per subscriber per 500 ms interval: [3](#0-2) 

`SharedTopicListener.listen()` allocates a per-subscriber `onBackpressureBuffer` of `maxBufferSize` (default 16,384 messages) and a `publishOn(Schedulers.boundedElastic())` slot for every subscriber: [4](#0-3) 

`TopicMessageServiceImpl.subscribeTopic()` only tracks subscriber count as a Micrometer gauge — it never enforces a maximum: [5](#0-4) 

**The only guard — `maxConcurrentCallsPerConnection = 5` — is per-connection, not global:** [6](#0-5) 

`GrpcConfiguration` applies this limit but sets no `maxConnections`, no `maxConnectionAge`, and no per-IP limit: [7](#0-6) 

No throttling equivalent to the `web3` module's `ThrottleManagerImpl` exists anywhere in the `grpc` module. [8](#0-7) 

**Root cause:** The server enforces 5 concurrent calls *per TCP connection* but places no bound on the number of TCP connections an unauthenticated client may open. Multiplying connections × 5 yields an unbounded global subscription count. No per-IP connection rate limit, no global subscription ceiling, and no gRPC-layer throttle exist.

**Failed assumption:** The design assumes that `maxConcurrentCallsPerConnection` is a sufficient DoS guard. It is not, because gRPC over HTTP/2 allows a single client to multiplex many streams across many connections, and nothing prevents opening thousands of connections from a single IP or a small botnet.

### Impact Explanation

- **POLL mode (default configurable):** Each subscription independently issues `topicMessageRepository.findByFilter()` every 500 ms. With 2,000 concurrent subscriptions the DB connection pool (typically 10–20 connections) is saturated within seconds; all subsequent queries — including those from legitimate subscribers — queue indefinitely or time out, making the node unresponsive.
- **All modes:** Each subscription allocates up to 16,384 `TopicMessage` objects in its backpressure buffer. At ~1 KB per message, 5,000 subscriptions consume ~80 GB of heap, triggering GC thrashing and OOM.
- **`boundedElastic()` scheduler:** Although bounded in threads, its task queue is unbounded; thousands of `publishOn` tasks pile up, delaying all reactive pipelines on the node.

The combined effect can render one or more gRPC mirror nodes completely unresponsive to all subsequent requests, satisfying the ≥30% network processing node shutdown threshold.

### Likelihood Explanation

No authentication is required to call `subscribeTopic`. The gRPC port (5600) is publicly exposed. Opening thousands of HTTP/2 connections is trivially achievable with standard tooling (`ghz`, `grpcurl` in a loop, or a simple Go/Python script). The attack is repeatable, requires no special knowledge beyond the public proto definition, and can be sustained indefinitely since subscriptions are long-lived streaming RPCs.

### Recommendation

1. **Add a global connection limit** in `GrpcConfiguration`: call `serverBuilder.maxConnectionAge(...)`, `serverBuilder.maxConnectionIdle(...)`, and use a Netty `ChannelOption` or a custom `ServerTransportFilter` to cap total simultaneous connections.
2. **Enforce a global subscription ceiling** in `TopicMessageServiceImpl.subscribeTopic()`: compare `subscriberCount.get()` against a configurable maximum and return `RESOURCE_EXHAUSTED` if exceeded.
3. **Add per-IP connection rate limiting** via a gRPC `ServerInterceptor` that tracks open streams per remote address and rejects new ones above a threshold.
4. **Expose `maxConcurrentCallsPerConnection` documentation** as insufficient alone and lower the default or add the above complementary controls.
5. For `POLL` mode specifically, consider enforcing a hard cap on the number of independent pollers to protect the DB connection pool.

### Proof of Concept

```bash
# Open 500 connections × 5 streams = 2500 concurrent subscriptions (POLL mode)
# Requires grpcurl and a valid topic ID (0.0.1000 used as example)
for i in $(seq 1 500); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":1000},"consensusStartTime":{"seconds":0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
# Each of the 2500 streams triggers an independent DB poll every 500ms
# DB connection pool (default ~10 connections) saturates within ~1s
# Observe: subsequent legitimate subscribeTopic calls hang or return UNAVAILABLE
# Monitor: hiero.mirror.grpc.subscribers gauge climbs to 2500 with no rejection
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/TopicListener.java (L18-18)
```java
    Flux<TopicMessage> listen(TopicMessageFilter filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/CompositeTopicListener.java (L35-44)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        if (!listenerProperties.isEnabled()) {
            return Flux.empty();
        }

        return getTopicListener()
                .listen(filter)
                .filter(t -> filterMessage(t, filter))
                .doOnNext(this::recordMetric);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L34-49)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        PollingContext context = new PollingContext(filter);
        Duration interval = listenerProperties.getInterval();

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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L17-35)
```java
class GrpcConfiguration {

    @Bean
    @Qualifier("readOnly")
    TransactionOperations transactionOperationsReadOnly(PlatformTransactionManager transactionManager) {
        var transactionTemplate = new TransactionTemplate(transactionManager);
        transactionTemplate.setReadOnly(true);
        return transactionTemplate;
    }

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
