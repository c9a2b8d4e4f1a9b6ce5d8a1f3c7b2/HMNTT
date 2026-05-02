I have verified all the code references. Let me check one more detail about the `NettyProperties` configuration and SECURITY.md scope.

All code references have been verified against the actual source. Every technical claim in the submission is accurate.

---

## Audit Report

## Title
Unbounded Concurrent Subscriptions Exhaust `boundedElastic()` Thread Pool via Blocking DB Calls in `PollingTopicListener.poll()`

## Summary
When `hiero.mirror.grpc.listener.type=POLL` is configured, each active `subscribeTopic` gRPC stream periodically occupies a thread from the global `Schedulers.boundedElastic()` pool for the full duration of a synchronous, blocking JDBC call (`getResultList()`). Because the endpoint is unauthenticated and there is no per-IP connection cap, an attacker opening enough concurrent streams saturates the thread pool, causing all subsequent poll tasks to queue indefinitely and halting live message delivery for every subscriber on the node.

## Finding Description

**Verified code path:**

`ConsensusController.subscribeTopic()` (no authentication, no rate limit) calls `topicMessageService.subscribeTopic()`: [1](#0-0) 

`TopicMessageServiceImpl.subscribeTopic()` calls `topicListener.listen(newFilter)` for the live stream: [2](#0-1) 

`PollingTopicListener` holds a single shared `Schedulers.boundedElastic()` instance (the global JVM-wide scheduler): [3](#0-2) 

`listen()` schedules every poll iteration on that scheduler via `delaySubscription` and `withScheduler`: [4](#0-3) 

`poll()` calls `findByFilter()` and wraps the result in `Flux.fromStream()`: [5](#0-4) 

`findByFilter()` is declared `@Transactional(readOnly = true)` and its implementation calls `typedQuery.getResultList()` — a fully synchronous, blocking JDBC call that materialises the entire result set before returning: [6](#0-5) [7](#0-6) 

**Root cause:** `delaySubscription(interval, scheduler)` causes the subscription to `Flux.defer(() -> poll(context))` to execute on a `boundedElastic()` worker thread. Because `poll()` immediately calls the blocking `getResultList()`, that worker thread is held for the full duration of the DB query. There is no `.timeout()` on the poll `Flux`, no per-subscription concurrency cap, and no rate limiting at the gRPC layer.

**Why existing checks are insufficient:**

- `maxPageSize = 5000` limits result-set size but does not bound query *execution time*. Under DB load induced by the attack itself, a `LIMIT 5000` query can take seconds. [8](#0-7) 

- `Schedulers.boundedElastic()` defaults to `10 × availableProcessors` threads (e.g. 80 on an 8-core host). Once all threads are occupied, new poll tasks queue in the 100,000-task internal queue; they do not execute until a thread is freed, causing unbounded delivery delay.

- `maxConcurrentCallsPerConnection = 5` limits concurrent calls *per connection* but places no cap on the total number of connections or total concurrent subscriptions across connections. [9](#0-8) 

- The same global `boundedElastic()` scheduler is also used by `PollingTopicMessageRetriever` and the safety-check path in `TopicMessageServiceImpl`, so saturation has a wider blast radius than the listener alone. [10](#0-9) [11](#0-10) 

## Impact Explanation
Every active `POLL`-mode subscription periodically occupies a `boundedElastic()` thread for the duration of a blocking DB query. With enough concurrent subscriptions the thread pool is fully saturated. New poll tasks queue but never execute within the polling interval (default 500 ms), so live topic messages are not delivered to any subscriber. Because the same global scheduler is shared across all subscriptions and across `PollingTopicMessageRetriever`, the impact is global — all subscribers on the node are affected simultaneously. This constitutes a complete denial of live message delivery for the duration of the attack. [12](#0-11) 

## Likelihood Explanation
The `subscribeTopic` gRPC endpoint is unauthenticated and publicly reachable. An attacker needs only a gRPC client (e.g. `grpcurl`) and the ability to open many TCP connections. The attack is self-amplifying: each new subscription adds DB load, which slows existing queries, which holds threads longer, which makes it easier for the next batch of subscriptions to saturate the pool. The attack is repeatable and requires no special knowledge beyond the public protobuf definition. The only prerequisite is that the operator has configured `hiero.mirror.grpc.listener.type=POLL` — a non-default but fully documented option. [13](#0-12) 

## Recommendation

1. **Replace the blocking call with a non-blocking alternative.** Use Spring Data R2DBC or a reactive JDBC driver so `findByFilter` returns a `Flux<TopicMessage>` without occupying a thread.
2. **Add a `.timeout()` to the poll `Flux`** in `PollingTopicListener.listen()` so a slow DB query releases the scheduler thread after a bounded interval.
3. **Cap concurrent subscriptions.** Introduce a global or per-IP semaphore/counter that rejects new `subscribeTopic` calls once a configurable limit is reached.
4. **Isolate the polling scheduler.** Replace `Schedulers.boundedElastic()` with a dedicated, bounded `Schedulers.newBoundedElastic(...)` instance scoped to `PollingTopicListener` so saturation cannot spill into `PollingTopicMessageRetriever` or the safety-check path.
5. **Add connection-level rate limiting** at the gRPC layer (e.g. via a `ServerInterceptor`) to complement the existing per-connection call cap.

## Proof of Concept

```bash
# Requires grpcurl and the mirror node running with listener.type=POLL
# Open N concurrent indefinite subscriptions (no endTime, no limit)
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
```

With 200 concurrent streams on an 8-core host (pool cap = 80 threads), every `boundedElastic()` thread is occupied by a blocking `getResultList()` call. The 500 ms poll interval fires for all 200 subscriptions simultaneously; 120 tasks queue behind the 80 running ones. Under induced DB load each query takes >500 ms, so the queue never drains — live message delivery halts for all subscribers until the attack connections are closed. [4](#0-3) [14](#0-13)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L70-70)
```java
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L120-121)
```java
        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-61)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustom.java (L12-13)
```java
    @Transactional(readOnly = true)
    Stream<TopicMessage> findByFilter(TopicMessageFilter filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L48-60)
```java
        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L26-26)
```java
    private int maxPageSize = 5000;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L30-30)
```java
    private Duration interval = Duration.ofMillis(500L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L37-37)
```java
    private ListenerType type = ListenerType.REDIS;
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
