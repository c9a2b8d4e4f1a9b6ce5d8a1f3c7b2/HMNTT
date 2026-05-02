### Title
Unbounded Polling Loop on Empty/Quiet Topics Enables Unauthenticated Resource Exhaustion via gRPC

### Summary
Any unauthenticated client can subscribe to any existing Hedera topic via the public gRPC `subscribeTopic` endpoint with no message limit set. When the topic is empty or quiet, `PollingTopicListener.listen()` enters a `RepeatSpec.times(Long.MAX_VALUE)` loop that issues a DB query every 500 ms for the entire lifetime of the connection. There is no cap on total concurrent subscriptions, no per-IP connection limit, and no rate limiting on the gRPC service, so an attacker opening many connections can generate a sustained, unbounded stream of empty DB queries.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (line 43–53) accepts any unauthenticated gRPC call and delegates to `TopicMessageServiceImpl.subscribeTopic()`. [1](#0-0) 

`TopicMessageServiceImpl.subscribeTopic()` calls `topicExists()` (line 87–91), which only checks that the entity row exists and has type `TOPIC`. It does **not** check whether the topic has any messages, and it does not impose any subscription quota. [2](#0-1) 

After the existence check passes, `incomingMessages()` calls `topicListener.listen(newFilter)`, which resolves to `PollingTopicListener.listen()`. [3](#0-2) 

Inside `PollingTopicListener.listen()`, the repeat operator is configured with `Long.MAX_VALUE` repetitions and a fixed delay of `interval` (default 500 ms). There is no early-exit condition when `poll()` returns an empty result set. [4](#0-3) 

`poll()` unconditionally calls `topicMessageRepository.findByFilter(newFilter)` on every tick, regardless of whether the previous call returned results. [5](#0-4) 

**Root cause:** The polling loop has no termination condition tied to empty results, no maximum subscription duration, and no global subscription count limit. The only termination paths are: the client disconnects, a `limit` is reached (requires the client to set one), or an `endTime` elapses (requires the client to set one).

**Why existing checks fail:**

- `checkTopicExists = true` (default) only rejects subscriptions to *non-existent* topics. A topic that exists but has zero messages passes this check and enters the infinite polling loop. [6](#0-5) 

- `maxConcurrentCallsPerConnection = 5` limits calls *per TCP connection*, but there is no limit on the number of connections from a single IP or on the total number of active subscriptions server-wide. [7](#0-6) 

- The throttle/rate-limit infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module and is not applied to the gRPC service at all. [8](#0-7) 

- The `subscriberCount` gauge is purely observational; it does not enforce any ceiling. [9](#0-8) 

- The `listenerProperties.interval` minimum is 50 ms, meaning the worst-case polling rate is 20 DB queries per second *per subscription*. [10](#0-9) 

### Impact Explanation

Each long-lived subscription to a quiet topic issues one DB query every `interval` (default 500 ms, minimum 50 ms) for as long as the TCP connection is held open. With N connections × 5 calls each, an attacker sustains N×5 × (1/interval) empty queries per second against the database. At the minimum interval of 50 ms this is 100 queries/second per connection. This exhausts the DB connection pool and the `boundedElastic` scheduler thread pool, degrading or denying service to legitimate subscribers. No credentials, tokens, or on-chain funds are required.

### Likelihood Explanation

The gRPC port (default 5600) is publicly reachable. Topic IDs are public on Hedera mainnet/testnet. A single attacker script can open hundreds of TCP connections (each carrying 5 streams) using any standard gRPC client (e.g., `grpcurl`, the Hedera Java/Go SDK). The attack is trivially repeatable, requires no special knowledge beyond a valid topic ID, and leaves no per-attacker audit trail since there is no authentication.

### Recommendation

1. **Enforce a global subscription ceiling:** Reject new subscriptions when `subscriberCount` exceeds a configurable maximum (e.g., `hiero.mirror.grpc.maxSubscribers`).
2. **Add a maximum subscription duration:** Terminate subscriptions that have been open longer than a configurable timeout with no messages received (analogous to `retriever.timeout`).
3. **Back off on empty polls:** When `poll()` returns zero results, apply exponential back-off up to a configurable ceiling instead of always using the fixed `interval`.
4. **Apply per-IP connection limits** at the Netty/load-balancer layer.
5. **Require `endTime` or `limit`** for subscriptions to topics with no recent activity, or add a gRPC-level rate limiter mirroring the `web3` `ThrottleConfiguration`.

### Proof of Concept

```bash
# 1. Identify any existing topic on the network (topic 0.0.41110 used as example)
# 2. Open 200 parallel subscriptions with no limit and no end time:
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 41110}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
# Each background process holds a streaming gRPC call open indefinitely.
# The server issues one DB query per subscription every 500 ms.
# 200 connections × 1 stream = 400 DB queries/second sustained with zero messages returned.
# Scale connections to exhaust the DB pool.
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-106)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }

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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L108-121)
```java
    private Flux<TopicMessage> incomingMessages(TopicContext topicContext) {
        if (topicContext.isComplete()) {
            return Flux.empty();
        }

        TopicMessageFilter filter = topicContext.getFilter();
        TopicMessage last = topicContext.getLast();
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();

        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-49)
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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-62)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L28-31)
```java
    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);

```
