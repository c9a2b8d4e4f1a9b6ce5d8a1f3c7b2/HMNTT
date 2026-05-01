### Title
Unbounded Concurrent `subscribeTopic()` Streams Enable Unauthenticated Resource Exhaustion DoS

### Summary
The `subscribeTopic()` gRPC endpoint in `ConsensusController` accepts connections from any unauthenticated caller with no global limit on total concurrent streams. The only guard — `maxConcurrentCallsPerConnection = 5` — is a per-connection limit, not a server-wide limit. An attacker opening thousands of TCP connections can create tens of thousands of indefinite, no-endTime streams, exhausting JVM heap, the `Schedulers.boundedElastic()` task queue, and (in POLL listener mode) the database connection pool, causing the node to become unresponsive.

### Finding Description

**Entry point — no authentication, no global stream gate:**

`ConsensusController.subscribeTopic()` ( [1](#0-0) ) calls `topicMessageService.subscribeTopic()` directly with no authentication check and no check against any global subscriber ceiling.

**`subscriberCount` is a metric, not a gate:**

`TopicMessageServiceImpl` maintains an `AtomicLong subscriberCount` ( [2](#0-1) ) that is incremented on subscribe and decremented on termination ( [3](#0-2) ). It is registered only as a Micrometer gauge — there is no `if (subscriberCount >= MAX) reject` guard anywhere.

**Streams with no `endTime` never self-terminate:**

When `endTime` is absent, `pastEndTime()` returns `Flux.never()` ( [4](#0-3) ), so `takeUntilOther` never fires. The live flux runs for `Long.MAX_VALUE` repeats ( [5](#0-4) ).

**Per-connection limit does not bound total streams:**

`GrpcConfiguration` sets only `maxConcurrentCallsPerConnection` ( [6](#0-5) ) to a default of 5 ( [7](#0-6) ). No `maxConnections`, no IP-based rate limit, and no total-stream ceiling is configured. An attacker with N TCP connections gets 5N concurrent streams.

**Scheduler and DB exhaustion (POLL listener mode):**

Each stream in POLL mode creates its own `PollingContext` and schedules `Long.MAX_VALUE` repeat tasks on the global `Schedulers.boundedElastic()` ( [8](#0-7) ). Each poll iteration calls `topicMessageRepository.findByFilter()`, consuming a DB connection. The retriever also uses the same global scheduler ( [9](#0-8) ). With thousands of streams, the scheduler's task queue (default 100 000 tasks × thread count) fills and begins throwing `RejectedExecutionException`, and the HikariCP pool is exhausted.

**Memory exhaustion (all listener modes):**

Even with the default REDIS listener, each stream allocates a `TopicContext`, a reactive pipeline chain, and a Redis subscription filter. Thousands of such objects exhaust JVM heap.

### Impact Explanation
An attacker can render the gRPC node completely unresponsive: JVM OOM kills the process, or DB connection pool exhaustion causes all DB-backed operations (including legitimate subscribers and the importer) to fail. Because the gRPC mirror node is the sole HCS subscription interface for downstream clients, its unavailability constitutes a ≥30% network processing disruption as described in the scope. No privileged access is required.

### Likelihood Explanation
The attack requires only a valid `topicId` (publicly observable on-chain) and the ability to open many TCP connections — trivially achievable with a single script using `grpcurl` or any gRPC client library. The attack is repeatable and requires no brute force. The default `maxConcurrentCallsPerConnection = 5` provides a false sense of protection while the absence of a total-connection or total-stream limit leaves the server fully exposed.

### Recommendation
1. Add a **global concurrent-stream ceiling** checked inside `TopicMessageServiceImpl.subscribeTopic()` before incrementing `subscriberCount`; return `RESOURCE_EXHAUSTED` when the ceiling is reached.
2. Configure `NettyServerBuilder.maxConnectionAge` / `maxConnectionAgeGrace` and a **total connection limit** in `GrpcConfiguration`.
3. Enforce a **mandatory `endTime`** or a **maximum stream lifetime** (e.g., 24 h) so streams cannot be held open indefinitely.
4. Add **per-IP or per-client rate limiting** at the gRPC interceptor layer (analogous to the `ThrottleConfiguration` used in the web3 module).
5. For POLL listener mode, use a **shared polling flux** (already available as `SharedPollingTopicListener`) rather than per-subscriber polling to decouple subscriber count from DB query rate.

### Proof of Concept
```bash
# Open 2000 TCP connections, each with 5 concurrent indefinite streams (10 000 total)
# Requires grpcurl and a valid topicId (e.g., 0.0.41110)

for i in $(seq 1 2000); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observable effect:
# 1. hiero.mirror.grpc.subscribers gauge climbs to ~10 000 with no ceiling rejection
# 2. JVM heap exhaustion (GC overhead limit exceeded) or
#    HikariCP pool exhaustion (in POLL mode) causes node crash/hang
# 3. Legitimate subscribers receive UNAVAILABLE or timeout errors
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L89-91)
```java
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-43)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();

    @Override
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        PollingContext context = new PollingContext(filter);
        Duration interval = listenerProperties.getInterval();

        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-33)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-41)
```java
        scheduler = Schedulers.boundedElastic();
```
