### Title
Unbounded Subscription Intake Exhausts Shared `boundedElastic()` Thread Pool, Denying Service to New Subscribers

### Summary
`PollingTopicListener` and `SharedTopicListener` both use the global `Schedulers.boundedElastic()` singleton for scheduling and executing blocking database poll operations. Because there is no rate limit or subscription cap enforced anywhere in the call chain, an unprivileged attacker can open enough concurrent subscriptions to saturate the bounded thread pool, causing all subsequent subscription setup tasks to queue indefinitely and eventually be rejected.

### Finding Description

**Shared global scheduler — all components converge on the same instance.**

`Schedulers.boundedElastic()` is a Reactor static factory that returns the **global singleton** bounded-elastic scheduler. Every call to it — whether in `PollingTopicListener`, `SharedPollingTopicListener`, or `SharedTopicListener` — returns the same object.

- `PollingTopicListener` stores it: [1](#0-0) 
- `SharedPollingTopicListener` stores it: [2](#0-1) 
- `SharedTopicListener.listen()` uses it inline for `publishOn`: [3](#0-2) 
- `TopicMessageServiceImpl` uses it for the safety-check mono: [4](#0-3) 

**Root cause — blocking DB query runs on the scheduler thread (POLL mode).**

In `PollingTopicListener.listen()`, `delaySubscription(interval, scheduler)` fires the subscription on a `boundedElastic()` thread. The upstream is `Flux.defer(() -> poll(context))`, which synchronously calls `topicMessageRepository.findByFilter(newFilter)` and wraps the result in `Flux.fromStream()`. Because there is no `subscribeOn` to offload the stream iteration, the blocking JDBC/stream call executes on — and holds — the scheduler thread for the full duration of the database query.

```
delaySubscription fires on boundedElastic thread
  → Flux.defer subscribes → poll() called on same thread
    → topicMessageRepository.findByFilter() [BLOCKING DB CALL]
      → Flux.fromStream iterates synchronously
        → thread held until query + iteration complete
``` [5](#0-4) [6](#0-5) 

**No rate limiting or subscription cap exists.**

`TopicMessageServiceImpl` tracks `subscriberCount` only as a Micrometer gauge — it is never checked against a maximum. There is no per-IP, per-client, or global subscription limit anywhere in the call chain. [7](#0-6) [8](#0-7) 

**Exploit flow.**

1. Attacker opens N concurrent gRPC `subscribeTopic` streams (no authentication required per the public API docs).
2. Each subscription in POLL mode schedules a `delaySubscription` task on the global `boundedElastic()` scheduler, then holds a thread for the duration of each DB poll.
3. The `boundedElastic()` thread cap is `10 × availableProcessors` (e.g., 40 threads on a 4-core host). With a 500 ms interval and a ~100 ms DB query, each thread is occupied ~20% of the time; ~200 concurrent subscriptions keep all 40 threads continuously busy.
4. New legitimate subscribers' `delaySubscription` tasks enter the task queue (capped at 100,000 entries). While the queue has space, new subscribers are delayed indefinitely. Once the queue fills, tasks are rejected with `RejectedExecutionException`, hard-failing new subscriptions.
5. The safety-check `subscribeOn(Schedulers.boundedElastic())` in `TopicMessageServiceImpl` also queues on the same exhausted pool, compounding the effect.

### Impact Explanation

In POLL mode, every active attacker subscription continuously consumes a thread from the shared global scheduler during blocking DB I/O. Legitimate new subscribers cannot get a scheduler thread to complete their setup, causing them to either wait indefinitely (queue phase) or receive a hard error (queue-full phase). This is a complete denial of the subscription service for new users while the attack is sustained, with no economic cost to the attacker beyond maintaining open TCP/gRPC connections.

### Likelihood Explanation

The attack requires only the ability to open gRPC connections — no credentials, no special privileges. The `subscribeTopic` endpoint is publicly documented and accessible via plain `grpcurl`. The number of subscriptions needed to exhaust the pool scales inversely with DB query latency; under any realistic load (slow DB, many topics), far fewer than 200 subscriptions may suffice. The attack is trivially repeatable and can be automated with any gRPC client library.

### Recommendation

1. **Enforce a global and per-client subscription cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable maximum.
2. **Decouple blocking DB I/O from the shared scheduler**: add an explicit `.subscribeOn(Schedulers.boundedElastic())` scoped to the poll flux only, or use a dedicated `Schedulers.newBoundedElastic(...)` instance in `PollingTopicListener` so attacker subscriptions cannot starve the global pool used by other components.
3. **Add gRPC-layer rate limiting** (e.g., via a `ServerInterceptor`) to limit connection/stream rates per source IP.
4. Consider switching POLL mode to use non-blocking DB access (R2DBC) so threads are not held during queries at all.

### Proof of Concept

```bash
# Open 300 concurrent long-lived subscriptions from a single unprivileged client
# (adjust topicNum to any valid topic)
for i in $(seq 1 300); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Now attempt a new subscription as a legitimate user:
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 41110}, "limit": 1}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected result: hangs indefinitely (queue phase) or
# fails with INTERNAL / RejectedExecutionException (queue-full phase)
```

The 300 background subscriptions saturate the `boundedElastic()` thread pool via concurrent blocking DB polls. The final legitimate subscription cannot acquire a scheduler thread to complete its `delaySubscription` setup, demonstrating the denial-of-service condition.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-48)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedPollingTopicListener.java (L37-37)
```java
        Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L25-25)
```java
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L70-70)
```java
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```
