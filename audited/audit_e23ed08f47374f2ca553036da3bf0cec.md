### Title
Unauthenticated gRPC Subscription Polling Causes Database Connection Pool Exhaustion (DoS)

### Summary
The `PollingTopicMessageRetriever.retrieve()` method, invoked for every `subscribeTopic` gRPC call with `throttled=true`, issues repeated database queries every 2 seconds for up to 60 seconds (≈30 queries) per subscription when a topic has sufficient historical messages. There is no global limit on concurrent subscriptions, no per-IP rate limiting, and no authentication on the gRPC endpoint, allowing any unauthenticated attacker to open many concurrent subscriptions and exhaust the HikariCP database connection pool.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `topicMessageRetriever.retrieve(filter, true)` → `PollingTopicMessageRetriever.retrieve()`

In `TopicMessageServiceImpl.subscribeTopic()`, the retriever is always called with `throttled=true`: [1](#0-0) 

In `PollingTopicMessageRetriever.retrieve()`, when `throttled=true`, the `PollingContext` constructor sets: [2](#0-1) 

- `numRepeats = Long.MAX_VALUE`
- `frequency = 2s` (default `pollingFrequency`)
- `maxPageSize = 1000`

The repeat loop runs until `isComplete()` returns true: [3](#0-2) 

`isComplete()` for throttled mode only returns `true` when the last page returned **fewer than `maxPageSize` (1000) messages**: [4](#0-3) 

For any topic with ≥1000 historical messages, every poll returns a full page, `isComplete()` stays `false`, and polling continues every 2 seconds until the 60-second idle timeout fires — yielding up to 30 DB queries per subscription. [5](#0-4) 

Each poll executes: [6](#0-5) 

**Why existing checks are insufficient:**

The only per-connection concurrency control is `maxConcurrentCallsPerConnection = 5`: [7](#0-6) 

This is applied per TCP connection, not globally. An attacker opens `C` connections × 5 calls each = `5C` concurrent subscriptions. There is no global subscription cap, no per-IP limit, and no authentication on `subscribeTopic`: [8](#0-7) 

The `subscriberCount` gauge is metrics-only, not a limit: [9](#0-8) 

Additionally, the `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` means DB failures (e.g., from pool exhaustion) trigger infinite retries, amplifying the attack: [10](#0-9) 

### Impact Explanation

The HikariCP pool for the gRPC service has no explicitly configured maximum in the codebase (defaults to 10 connections). With `N` concurrent subscriptions each polling every 2 seconds, the number of simultaneous in-flight DB queries scales linearly with `N`. Once the pool is exhausted, all DB operations across the gRPC service fail — including legitimate subscriptions, entity existence checks, and listener queries — resulting in a complete service-level denial of service. The `retryWhen(Long.MAX_VALUE)` retry loop on each subscription further amplifies pool pressure after exhaustion begins.

### Likelihood Explanation

The attack requires no credentials, no special network position, and no prior knowledge beyond a valid topic ID with sufficient historical messages (common on Hedera mainnet/testnet where topics with millions of messages exist). The attacker needs only a standard gRPC client (e.g., `grpcurl`) and the ability to open multiple TCP connections. The attack is fully repeatable and automatable. The `maxConcurrentCallsPerConnection = 5` limit means an attacker needs only `ceil(pool_size / 5)` connections to saturate the pool — typically just 2 connections.

### Recommendation

1. **Add a global concurrent subscription limit**: Track active subscriptions in `TopicMessageServiceImpl` and reject new ones above a configurable threshold (e.g., 100).
2. **Add per-IP rate limiting** at the gRPC interceptor layer, similar to the `bucket4j`-based throttling used in the web3 module.
3. **Cap the maximum number of polls per throttled subscription**: Introduce a `maxPolls` limit for throttled mode analogous to `unthrottled.maxPolls = 12`, preventing indefinite polling per subscription.
4. **Use a dedicated, bounded thread pool** for retriever polling so that pool exhaustion is isolated from other DB operations.
5. **Set an explicit HikariCP `maximumPoolSize`** for the gRPC datasource and configure a short `connectionTimeout` to fail fast rather than queue indefinitely.

### Proof of Concept

**Preconditions:**
- Mirror node gRPC endpoint accessible on port 5600
- A topic ID (e.g., `0.0.41110`) with ≥1000 historical messages

**Steps:**

```bash
# Open 4 connections × 5 concurrent subscriptions = 20 concurrent subscriptions
# Each subscription polls DB every 2s for up to 60s = ~30 queries each = 600 total queries

for i in $(seq 1 20); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 41110}, "consensusStartTime": {"seconds": 0}}' \
    localhost:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Monitor DB connection pool exhaustion via metrics:
# hikaricp_connections_pending > 0 and hikaricp_connections_active == hikaricp_connections_max
# Legitimate subscriptions will begin receiving DEADLINE_EXCEEDED or UNAVAILABLE errors
```

**Result:** The HikariCP pool is saturated. New DB operations (including legitimate subscriptions and entity lookups) queue or fail with connection timeout errors, causing a service-level DoS for all gRPC clients.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-55)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L58-58)
```java
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L77-78)
```java
        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L98-101)
```java
            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L124-125)
```java
            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L25-28)
```java
    private Duration pollingFrequency = Duration.ofSeconds(2L);

    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```
