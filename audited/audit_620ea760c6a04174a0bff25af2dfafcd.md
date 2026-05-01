### Title
Unauthenticated Unbounded Concurrent gRPC Subscriptions Enable Database Exhaustion via Session Churn

### Summary
The `PollingTopicMessageRetriever.retrieve()` method accepts any unauthenticated gRPC client and issues repeated database queries every 2 seconds per session with no global cap on concurrent subscriptions. The only per-connection limit (`maxConcurrentCallsPerConnection=5`) is trivially bypassed by opening many TCP connections, allowing an attacker to drive unbounded parallel DB polling loops that exhaust the database connection pool and CPU.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (no auth check) → `TopicMessageServiceImpl.subscribeTopic()` → `topicMessageRetriever.retrieve(filter, true)` → `PollingTopicMessageRetriever.retrieve()`.

**Root cause — three compounding gaps:**

1. **No global subscription limit.** `TopicMessageServiceImpl` tracks `subscriberCount` only as a Micrometer gauge metric — it is never checked against a ceiling. [1](#0-0) 

2. **Per-connection cap is not a global cap.** `GrpcConfiguration` sets `maxConcurrentCallsPerConnection=5`, which limits calls on a single TCP connection but places no bound on the number of TCP connections an attacker may open. [2](#0-1) [3](#0-2) 

3. **Each session issues unbounded DB queries.** In throttled mode `numRepeats = Long.MAX_VALUE` and `frequency = pollingFrequency` (default 2 s). Every poll calls `topicMessageRepository.findByFilter()`, which executes a full `getResultList()` — loading up to `maxPageSize=1000` rows into heap — every 2 seconds per session. [4](#0-3) [5](#0-4) [6](#0-5) 

**Timeout semantics amplify churn.** `.timeout(retrieverProperties.getTimeout(), scheduler)` fires only when no item is emitted within 60 s. An attacker subscribing to a topic with no new messages gets a predictable 60 s window of polling, then reconnects immediately, maintaining a steady-state army of sessions. [7](#0-6) [8](#0-7) 

**No authentication anywhere in the path.** `ConsensusController` performs no credential check; `topicExists()` only validates that the entity type is `TOPIC`, not that the caller has any right to read it. [9](#0-8) [10](#0-9) 

### Impact Explanation

With N TCP connections × 5 calls each, an attacker sustains N×5 concurrent DB queries firing every 2 seconds. Each query loads up to 1,000 rows into JVM heap. At modest scale (e.g., 200 connections = 1,000 concurrent sessions), the database receives 500 queries/second, each scanning the `topic_message` table. This exhausts the JDBC/R2DBC connection pool, starves legitimate subscribers, and can OOM the JVM through repeated large `ArrayList` allocations. The churn cycle (reconnect every ~60 s) keeps the attack self-sustaining with minimal client-side effort. Severity: **High** (availability impact, no privilege required).

### Likelihood Explanation

The gRPC port (default 5600) is typically internet-exposed. The attack requires only a standard gRPC client (e.g., `grpcurl`) and knowledge of any valid topic ID (topic IDs are public on-chain). No credentials, no tokens, no prior relationship with the service is needed. The attack is fully scriptable, repeatable, and can be distributed across multiple source IPs to avoid any upstream network-layer rate limiting.

### Recommendation

1. **Enforce a global concurrent-subscription ceiling** — check `subscriberCount` against a configurable `maxSubscribers` property before allowing a new subscription; return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-source-IP or per-client-identity rate limiting** at the gRPC interceptor layer (e.g., a `ServerInterceptor` backed by a token-bucket per remote address).
3. **Set a `maxConnections` limit** on the Netty server builder alongside `maxConcurrentCallsPerConnection` to bound total TCP connections.
4. **Reduce the default polling frequency** or add backpressure so that sessions with no downstream consumer do not issue full-page DB queries at the maximum rate.
5. **Consider requiring authentication** (mTLS or a bearer token) for `subscribeTopic` to prevent fully anonymous abuse.

### Proof of Concept

```bash
# Open 200 parallel gRPC connections, 5 streams each = 1000 concurrent sessions
# Each session subscribes from the beginning of time on a known topic

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110},
           "consensusStartTime": {"seconds": 0, "nanos": 0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observe: DB CPU spikes, connection pool saturates, legitimate subscribers
# receive UNAVAILABLE or extreme latency. Sessions auto-reconnect every ~60s
# when the topic has no new messages, maintaining continuous load.
```

Preconditions: network access to port 5600, any valid `topicNum` (publicly discoverable). No credentials required.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-55)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-105)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-34)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-59)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L94-107)
```java
        private PollingContext(TopicMessageFilter filter, boolean throttled) {
            this.filter = filter;
            this.throttled = throttled;

            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-60)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L27-28)
```java
    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```

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
