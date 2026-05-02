### Title
Unbounded Historical Replay via `startTime=0` in `PollingTopicListener` Causes Sustained Maximum-Rate Database Polling

### Summary
When `PollingTopicListener` is active (`type=POLL`), an unprivileged subscriber can set `startTime=0` (epoch), which passes all input validation. On a high-volume topic, every `poll()` invocation returns exactly `maxPageSize=5000` rows, causing the poller to issue a full-page database query every 500 ms indefinitely. Multiple concurrent subscriptions of this kind compound the database load with no per-subscriber throttle or lookback-window cap, degrading service for all subscribers sharing the same database.

### Finding Description

**Code path:**

`TopicMessageFilter` accepts `startTime=0` because:
- `@Min(0)` explicitly permits zero [1](#0-0) 
- `isValidStartTime()` checks `startTime <= DomainUtils.now()`, and since `DomainUtils.now()` returns current nanoseconds (always >> 0), the condition `0 <= now()` is always true [2](#0-1) 

Inside `PollingTopicListener.poll()`:
- With no `limit` set, `limit = Integer.MAX_VALUE` [3](#0-2) 
- `pageSize = Math.min(Integer.MAX_VALUE, 5000) = 5000` [4](#0-3) 
- On the first cycle `last == null`, so `startTime = filter.getStartTime() = 0` [5](#0-4) 
- A JPA query `WHERE topic_id=? AND consensus_timestamp >= 0 ORDER BY consensus_timestamp LIMIT 5000` is issued [6](#0-5) 

The polling loop repeats with `Long.MAX_VALUE` iterations and a fixed 500 ms delay: [7](#0-6) 

On a topic where new messages arrive faster than 5000/500 ms, or where the subscriber has not yet caught up to the tip, every cycle returns exactly 5000 rows. There is no mechanism to detect this "full-page" condition and back off, throttle, or reject the subscription. Each subscriber gets its own independent `PollingContext` and issues its own independent database queries. [8](#0-7) 

**Existing checks that fail:**
- `@Min(0)` on `startTime` explicitly allows 0 — no minimum lookback window enforced [1](#0-0) 
- `isValidStartTime()` is satisfied by 0 [2](#0-1) 
- `maxPageSize=5000` caps each query but does not prevent continuous full-page polling [9](#0-8) 
- `interval=500ms` is a fixed floor with only 10% jitter — no adaptive back-pressure [10](#0-9) 
- No per-subscriber connection limit or query-rate limit exists anywhere in the stack [8](#0-7) 

### Impact Explanation

Each malicious subscription drives a sustained stream of 5000-row JPA queries against PostgreSQL every ~500 ms. The `findByFilter` implementation loads the full result list into memory before streaming (`getResultList().stream()`), meaning each query holds a database cursor and heap allocation for 5000 `TopicMessage` objects. [11](#0-10) 

With N concurrent such subscriptions, the database receives N × 2 queries/second (each 5000 rows). This saturates connection pools, increases I/O wait, and degrades query latency for all other subscribers sharing the same PostgreSQL instance — including legitimate live-message subscribers whose polling cycles are delayed proportionally to database saturation.

### Likelihood Explanation

**Preconditions:**
1. Server must be configured with `hiero.mirror.grpc.listener.type=POLL` (non-default; default is `REDIS`) [12](#0-11) 
2. A topic with a large message history must exist (any public Hedera topic qualifies on mainnet)
3. Attacker needs only a gRPC client — no credentials required

**Feasibility:** Any unauthenticated client can open a `subscribeTopic` gRPC call with `consensusStartTime={seconds:0, nanos:0}` and no `limit`. The protobuf timestamp `{seconds:0}` maps to Unix epoch, which passes `isValidStartTime()`. Opening dozens of such subscriptions from a single machine is trivial. [13](#0-12) 

### Recommendation

1. **Enforce a minimum `startTime` floor**: Reject or clamp `startTime` values older than a configurable maximum lookback window (e.g., 24 hours before `now()`).
2. **Detect full-page responses and apply back-off**: If `poll()` returns exactly `maxPageSize` results, increase the polling interval exponentially until the subscriber catches up, similar to the `isComplete()` logic in `PollingTopicMessageRetriever`. [14](#0-13) 
3. **Add per-subscriber query rate limiting** at the gRPC controller or service layer.
4. **Cap concurrent subscriptions per client IP** using gRPC interceptors.

### Proof of Concept

```python
import grpc
from hedera import consensus_service_pb2_grpc, consensus_service_pb2
from hedera.proto import timestamp_pb2, basic_types_pb2

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

# startTime = Unix epoch (0), no limit, high-volume topic
query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=<high_volume_topic>),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    # limit intentionally omitted
)

# Open N concurrent subscriptions
for _ in range(50):
    threading.Thread(target=lambda: list(stub.subscribeTopic(query))).start()

# Result: 50 × 2 queries/sec of 5000 rows each hit PostgreSQL continuously
# Database CPU/IO saturates; legitimate subscriber poll latency degrades
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L28-31)
```java
    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-56)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L57-57)
```java
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L58-59)
```java
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L38-52)
```java
        Predicate predicate = cb.and(
                cb.equal(root.get(TOPIC_ID), filter.getTopicId()),
                cb.greaterThanOrEqualTo(root.get(CONSENSUS_TIMESTAMP), filter.getStartTime()));

        if (filter.getEndTime() != null) {
            predicate = cb.and(predicate, cb.lessThan(root.get(CONSENSUS_TIMESTAMP), filter.getEndTime()));
        }

        query = query.select(root).where(predicate).orderBy(cb.asc(root.get(CONSENSUS_TIMESTAMP)));

        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-60)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L26-26)
```java
    private int maxPageSize = 5000;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L29-30)
```java
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L62-65)
```java
        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L121-128)
```java
        boolean isComplete() {
            boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();

            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
            }

            return limitHit;
```
