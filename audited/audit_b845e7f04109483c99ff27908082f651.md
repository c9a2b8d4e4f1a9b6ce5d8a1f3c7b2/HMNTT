### Title
Unauthenticated gRPC `subscribeTopic` Endpoint Lacks Global Connection/Subscriber Cap, Enabling DB Exhaustion via Concurrent Stream Flood

### Summary
The `subscribeTopic` gRPC endpoint accepts unlimited unauthenticated connections. The only server-side guard is a per-connection call cap (`maxConcurrentCallsPerConnection=5`), but there is no limit on the number of inbound connections and no global subscriber ceiling. Each accepted stream unconditionally invokes `PollingTopicMessageRetriever.retrieve()`, which issues repeated `findByFilter` queries against the `topic_message` table. An attacker opening hundreds of connections (each carrying 5 streams) with `startTime=0` saturates the DB connection pool and degrades or denies service to legitimate subscribers.

### Finding Description

**Entry point — no auth, no global cap:**
`ConsensusController.subscribeTopic()` accepts every incoming call and immediately chains it into `topicMessageService.subscribeTopic(filter)` with no authentication check, no per-IP limit, and no check against any maximum subscriber count. [1](#0-0) 

**Per-connection cap is not a global cap:**
`GrpcConfiguration` configures `maxConcurrentCallsPerConnection` (default 5) but never calls `maxInboundConnections` or any equivalent. An attacker opens N TCP connections × 5 streams = N×5 concurrent active streams, all accepted. [2](#0-1) [3](#0-2) 

**`subscriberCount` is a metric, not a gate:**
`TopicMessageServiceImpl` tracks active subscribers in an `AtomicLong` and exposes it as a Micrometer gauge, but never reads it back to reject new subscriptions. Every call proceeds unconditionally to `topicMessageRetriever.retrieve(filter, true)`. [4](#0-3) [5](#0-4) 

**Each stream drives repeated DB polling:**
`PollingTopicMessageRetriever.retrieve()` creates a `PollingContext` per stream and enters a `repeatWhen` loop that calls `topicMessageRepository.findByFilter(newFilter)` on every tick. With `startTime=0` and no limit set, the throttled path repeats indefinitely (`numRepeats = Long.MAX_VALUE`) at `pollingFrequency` (default 2 s), issuing a full historical scan from sequence 0 on each poll. [6](#0-5) [7](#0-6) 

**No rate limiting exists in the gRPC module:**
The `ThrottleConfiguration` / `ThrottleManagerImpl` (bucket4j-based) lives exclusively in the `web3` module. There is no equivalent interceptor, filter, or token-bucket guard anywhere under `grpc/src/main/`. [8](#0-7) 

### Impact Explanation
Each attacker-controlled stream holds a live DB cursor and re-queries the `topic_message` table every 2 seconds from timestamp 0. With hundreds of concurrent streams the R2DBC/JDBC connection pool is exhausted, causing legitimate subscriber queries to queue or time out. The `hiero.mirror.grpc.subscribers` gauge spikes but triggers no protective action. Result: full denial of service for the gRPC tier and potential cascading load on the database shared with the importer and REST API. Severity: **High** (unauthenticated, remotely exploitable, service-wide impact).

### Likelihood Explanation
Preconditions are minimal: network access to port 5600, any gRPC client (e.g., `grpcurl`, the Hedera Java SDK). The attack is trivially scriptable, requires no credentials, and is repeatable. The per-connection call cap of 5 actually makes the attack cheaper — the attacker multiplexes 5 streams per TCP connection, reducing OS-level connection overhead while maximising DB load.

### Recommendation
1. **Add a global inbound connection limit** in `GrpcConfiguration` via `NettyServerBuilder.maxConnectionsTotal()` (or Netty's `maxInboundConnections`).
2. **Enforce a maximum concurrent subscriber count** in `TopicMessageServiceImpl.subscribeTopic()`: read `subscriberCount` before proceeding and return `RESOURCE_EXHAUSTED` if a configurable ceiling is exceeded.
3. **Add per-IP stream rate limiting** via a gRPC `ServerInterceptor` (e.g., using bucket4j, mirroring the pattern already used in the `web3` module).
4. **Require a non-zero `startTime`** or cap the historical scan window to prevent full-table scans from time 0.
5. **Expose `maxSubscribers` as a configurable property** in `GrpcProperties` alongside the existing `netty` block.

### Proof of Concept
```bash
# Open 100 connections, each with 5 concurrent streams (500 total), all scanning from epoch 0
for i in $(seq 1 100); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0,"nanos":0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait
```
Expected result: `hiero.mirror.grpc.subscribers` gauge reaches 500; DB connection pool saturates; subsequent legitimate `subscribeTopic` calls time out or receive `UNAVAILABLE`; `PollingTopicMessageRetriever` logs show 500 concurrent polling loops each issuing `findByFilter` from `startTime=0`.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L45-63)
```java
    public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
        if (!retrieverProperties.isEnabled()) {
            return Flux.empty();
        }

        PollingContext context = new PollingContext(filter, throttled);
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
                .doOnCancel(context::onComplete)
                .doOnComplete(context::onComplete)
                .doOnNext(context::onNext);
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-32)
```java
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
```
