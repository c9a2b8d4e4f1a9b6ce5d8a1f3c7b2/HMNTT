### Title
Unbounded Concurrent Subscriptions via `subscribeTopic()` Enable Resource Exhaustion DoS

### Summary
`TopicMessageServiceImpl.subscribeTopic()` imposes no global cap on the total number of active subscriptions. The `subscriberCount` field is a metrics-only gauge with no enforcement gate. The sole server-side defense — `maxConcurrentCallsPerConnection = 5` — is scoped per TCP connection, so an unauthenticated attacker opening many connections multiplies the subscription count without bound, exhausting memory, the `boundedElastic` scheduler task queue, and the DB connection pool.

### Finding Description

**Exact code path:**

`subscribeTopic()` unconditionally increments `subscriberCount` on every new subscription with no prior check: [1](#0-0) 

`subscriberCount` is registered only as a Micrometer `Gauge` — a read-only metric — with no enforcement logic anywhere in the class: [2](#0-1) 

Each subscription without an `endTime` runs indefinitely because `pastEndTime()` returns `Flux.never()`: [3](#0-2) 

Each subscription also schedules a recurring safety-check task on `Schedulers.boundedElastic()`: [4](#0-3) 

**The only server-side limit** is `maxConcurrentCallsPerConnection = 5`, applied in `GrpcConfiguration`: [5](#0-4) [6](#0-5) 

This limit is **per-connection only**. No total-connection limit, no per-IP limit, and no authentication interceptor is configured. An attacker opening N TCP connections gets N × 5 concurrent subscriptions.

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection` bounds total server load. It does not — it only bounds load per individual TCP connection, and there is no complementary global connection cap or subscription cap.

### Impact Explanation

Each long-lived subscription (no `endTime`, no `limit`) holds:
1. A `TopicContext` object + full Reactor Flux chain in heap memory
2. A live `topicListener.listen()` subscription (Redis channel or polling loop)
3. A pending task slot in `Schedulers.boundedElastic()` (default queue cap: 100,000 tasks; default thread cap: `10 × CPU cores`)
4. Potential DB connection usage during historical retrieval via `topicMessageRetriever.retrieve()`

With enough connections, the attacker can: exhaust JVM heap causing OOM; fill the `boundedElastic` task queue causing `RejectedExecutionException` for all subsequent safety-check tasks; and saturate the HikariCP DB connection pool (monitored via `GrpcHighDBConnections` alert), blocking legitimate historical retrieval for real subscribers. The mirror node's primary function — delivering topic messages to legitimate observers of Hedera transactions — is denied. [7](#0-6) 

### Likelihood Explanation

**Preconditions:** None. No authentication, no API key, no account required. The gRPC port (5600) is publicly exposed.

**Feasibility:** Opening thousands of TCP connections from a single machine or a small botnet is trivial. Each connection carries 5 subscriptions. A single attacker machine with 2,000 TCP connections produces 10,000 concurrent indefinite subscriptions. Standard gRPC client libraries (e.g., `grpc-java`, `grpcurl`) make this scriptable in minutes.

**Repeatability:** Fully repeatable. Connections can be re-opened immediately after any server-side timeout. There is no backoff, ban, or circuit-breaker applied to the caller.

### Recommendation

1. **Enforce a global subscription cap** inside `subscribeTopic()`: check `subscriberCount` before incrementing and return an error (e.g., `RESOURCE_EXHAUSTED` gRPC status) if the cap is exceeded.
2. **Add a per-IP connection limit** via a Netty `ServerBuilder` customizer (e.g., `maxConnectionsPerIp`) or an external load-balancer rule.
3. **Set `maxConnectionAge` and `maxConnectionIdle`** on the `NettyServerBuilder` to reclaim resources from idle or long-lived attacker connections.
4. **Add a gRPC server interceptor** that tracks and limits subscriptions per remote peer address.

### Proof of Concept

```bash
# Requires grpcurl and a valid topic ID (e.g., 0.0.1234) on the target
for i in $(seq 1 2000); do
  grpcurl -plaintext \
    -d '{"topicID":{"topicNum":1234},"consensusStartTime":{"seconds":0}}' \
    <TARGET_HOST>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
# 2000 connections × 5 calls/connection = 10,000 concurrent indefinite subscriptions
# Monitor: hiero_mirror_grpc_subscribers metric climbs unboundedly
# Result: JVM heap exhaustion / boundedElastic queue overflow / DB pool saturation
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-92)
```java
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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
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
