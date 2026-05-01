### Title
Unbounded Concurrent Polling Subscriptions Cause DB Exhaustion via `PollingTopicListener.listen()`

### Summary
`PollingTopicListener.listen()` creates a fully independent, per-subscriber polling loop that issues a raw DB query every 500ms with no cap on concurrent subscriptions, no per-client rate limiting, and no query deduplication. An unprivileged attacker opening many gRPC connections and subscribing to a large topic can saturate the database connection pool and thrash the DB page cache, degrading service for all users.

### Finding Description

**Exact code path:**

`PollingTopicListener.listen()` (lines 34–49) creates a new `PollingContext` per call and schedules an infinite repeat loop (`Long.MAX_VALUE` iterations) that fires every `interval` (default 500 ms): [1](#0-0) 

Each iteration calls `poll()` (lines 51–62), which directly executes `topicMessageRepository.findByFilter(newFilter)` — a raw DB query returning up to `maxPageSize` (default 5 000) rows: [2](#0-1) 

There is no shared state between subscriber instances; every subscription is a cold publisher with its own independent DB polling loop.

**Root cause — failed assumptions:**

1. No maximum concurrent subscription count is enforced. `TopicMessageServiceImpl` only tracks `subscriberCount` as a metrics gauge — it never rejects new subscriptions: [3](#0-2) 

2. The only connection-level guard is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`, which limits calls *per TCP connection* but places no bound on the total number of connections an attacker may open: [4](#0-3) 

3. The throttling infrastructure (Bucket4j) exists only in the `web3` module; there is no equivalent rate limiter in the `grpc` module for `subscribeTopic` calls.

4. `TopicMessageFilter` performs only semantic validation (start/end time ordering, `@Min(0)` on limit) — no per-client or per-topic subscription cap: [5](#0-4) 

5. `ConsensusController.subscribeTopic()` passes the filter directly to the service with no authentication or subscription-count check: [6](#0-5) 

**Why the `SHARED_POLL` alternative does not help here:** `SharedPollingTopicListener` uses a single shared `Flux` for all subscribers, which would mitigate this. However, `PollingTopicListener` (type `POLL`) is a distinct named bean that is fully wired and deployable via `hiero.mirror.grpc.listener.type=POLL`: [7](#0-6) 

### Impact Explanation
With N concurrent subscriptions all targeting the same large topic and `startTime` set to a historical timestamp, the DB receives N independent queries every 500 ms, each potentially scanning and returning up to 5 000 rows. This:
- Exhausts the DB connection pool, blocking legitimate queries.
- Evicts hot pages from the DB buffer cache (cache thrashing), increasing I/O latency for all queries across the mirror node.
- Causes CPU saturation on the DB server from repeated full or large index scans.
- Degrades or denies service to all other mirror node consumers (REST API, other gRPC subscribers).

Severity: **High** (availability impact on shared infrastructure with no economic barrier to the attacker).

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is unauthenticated and publicly reachable. An attacker needs only a gRPC client (e.g., `grpcurl`, the Hedera SDK, or a trivial script). Opening hundreds of connections each with 5 streams (the per-connection limit) requires no special privileges, no tokens, and no prior knowledge beyond a valid `topicId`. The attack is trivially repeatable and scriptable.

### Recommendation
1. **Enforce a global and per-IP concurrent subscription cap** in `TopicMessageServiceImpl.subscribeTopic()` — reject new subscriptions when the count exceeds a configurable threshold.
2. **Add gRPC-layer rate limiting** (e.g., Bucket4j interceptor) analogous to the `web3` throttle, keyed on remote IP.
3. **Prefer `SHARED_POLL` or `REDIS` over `POLL`** in production and document that `POLL` mode is unsafe for public-facing deployments.
4. **Cap `maxPageSize` per subscription** and enforce a minimum `startTime` recency window to bound query cost.

### Proof of Concept
```bash
# Prerequisites: grpcurl installed, mirror node running with POLL listener type,
# a topic with a large message history (e.g., topicId = 0.0.12345)

for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{
      "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 12345},
      "consensusStartTime": {"seconds": 0, "nanos": 0}
    }' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
```

Each background process holds an open gRPC stream. The mirror node issues 200 independent DB queries every 500 ms, each fetching up to 5 000 rows from the same large topic, rapidly exhausting the DB connection pool and degrading service for all users.

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-51)
```java
    public boolean hasLimit() {
        return limit > 0;
    }

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L36-43)
```java
    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```
