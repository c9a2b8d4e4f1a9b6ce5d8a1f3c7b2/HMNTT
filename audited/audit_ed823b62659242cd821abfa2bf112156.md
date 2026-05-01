### Title
Unauthenticated Unlimited Concurrent gRPC Subscriptions Enable Resource Exhaustion DoS

### Summary
The `TopicListener.listen()` interface and its entire call chain — `ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `TopicListener.listen()` — impose no authentication, no per-client rate limiting, and no maximum concurrent subscription cap. Any unauthenticated external caller can open an unbounded number of concurrent gRPC streaming subscriptions, exhausting per-subscriber memory buffers, the `boundedElastic` thread pool, and (in POLL mode) the database connection pool, denying service to legitimate subscribers.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) accepts any inbound gRPC call and immediately delegates to `topicMessageService.subscribeTopic()` with no authentication check, no IP-based throttle, and no connection count gate. [1](#0-0) 

`TopicMessageServiceImpl.subscribeTopic()` (lines 59–91) increments `subscriberCount` as a **metric gauge only** — it is never compared against a maximum and never used to reject a subscription. Every call unconditionally allocates a `TopicContext`, starts a historical retrieval flux, a live listener flux, and a 1-second safety-check flux. [2](#0-1) 

`SharedTopicListener.listen()` (lines 21–26) allocates a **per-subscriber** `onBackpressureBuffer` of up to 16 384 items and calls `publishOn(Schedulers.boundedElastic())`, consuming one thread from the bounded-elastic pool per active subscriber. [3](#0-2) 

`PollingTopicListener.listen()` (lines 34–49) creates a **new independent** `PollingContext` and a new `Flux.defer(() -> poll(context))` that issues a DB query every 500 ms for each subscription — there is no sharing of the polling loop across subscribers in this mode. [4](#0-3) 

**Root cause / failed assumption:** The design assumes that the number of concurrent subscribers will be bounded by legitimate client demand. There is no authentication layer on the gRPC service (no `*Security*.java` exists in the grpc module, and the only `GrpcInterceptor` found only sets an endpoint-context label), no per-IP or global subscription count limit, and no rate limiter on new subscription establishment. The `subscriberCount` field is wired only to a Micrometer gauge for observability, not to any admission-control logic. [5](#0-4) 

The only existing "check" is `topicExists()`, which validates that the requested topic ID is a known entity — it is not a security control and does not limit subscription volume. [6](#0-5) 

Rate limiting and throttling exist only in the `web3` module (`ThrottleConfiguration`, `ThrottleManagerImpl`) and the `rest` module (`authHandler.js`); neither applies to the gRPC listener path.

### Impact Explanation

**Memory exhaustion:** Each subscriber in REDIS or SHARED_POLL mode receives its own `onBackpressureBuffer(16384)`. With N=10 000 concurrent subscriptions and modest message sizes (e.g., 1 KB each), the buffer headroom alone is ~160 GB. Even at low message rates the JVM heap is exhausted, triggering OOM errors or GC thrashing that stalls all subscribers.

**Thread pool exhaustion:** `Schedulers.boundedElastic()` defaults to `10 × CPU cores` threads with an unbounded task queue. Thousands of subscribers saturate the pool, causing legitimate subscribers' reactive pipelines to queue indefinitely and effectively freeze.

**DB connection exhaustion (POLL mode):** Each `PollingTopicListener.listen()` call issues an independent DB query every 500 ms. N concurrent subscriptions = N concurrent DB queries every 500 ms, rapidly exhausting the JDBC/R2DBC connection pool and starving the importer and other services that share the same database.

Severity: **High** — complete denial of service to all legitimate subscribers with no collateral damage to the attacker.

### Likelihood Explanation

The gRPC port is publicly reachable by design (it is the Mirror Node's public HCS subscription endpoint). No credentials, tokens, or prior account registration are required. A single attacker with a commodity machine and a standard gRPC client library (e.g., `grpc-java`, `grpcurl`) can script thousands of concurrent `subscribeTopic` streaming calls in seconds. The attack is trivially repeatable and requires no special knowledge beyond the published protobuf API.

### Recommendation

1. **Enforce a global and per-IP concurrent subscription limit** in `TopicMessageServiceImpl.subscribeTopic()`: compare `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` status when exceeded. Add a per-source-IP counter using a gRPC `ServerInterceptor` that reads `io.grpc.Grpc.TRANSPORT_ATTR_REMOTE_ADDR`.

2. **Add a rate-limiting `ServerInterceptor`** (analogous to `ThrottleManagerImpl` in the web3 module) that throttles new subscription establishment per IP using a token-bucket algorithm (e.g., Bucket4j).

3. **Add authentication** (mTLS or a bearer-token interceptor) so that only authorized clients can open subscriptions, mirroring the `authHandler.js` pattern used by the REST module.

4. **Cap `maxBufferSize`** per subscriber and enforce a hard JVM heap budget for total in-flight buffers.

5. In POLL mode, consider migrating all callers to SHARED_POLL or REDIS to eliminate per-subscriber DB polling.

### Proof of Concept

```bash
# Prerequisites: grpcurl installed, mirror node gRPC port reachable at $HOST:5600
# Proto: com.hedera.mirror.api.proto.ConsensusService/subscribeTopic

for i in $(seq 1 5000); do
  grpcurl -plaintext \
    -d '{"topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1}}' \
    $HOST:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    > /dev/null 2>&1 &
done

# Each background process holds an open gRPC streaming call.
# In POLL mode: 5000 × DB query every 500ms = 10 000 DB queries/s → connection pool exhausted.
# In any mode: 5000 × 16384-item buffer → heap exhaustion.
# Legitimate subscribers begin receiving errors or stalling within seconds.
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-91)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }

    @Override
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });

        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }

        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
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
