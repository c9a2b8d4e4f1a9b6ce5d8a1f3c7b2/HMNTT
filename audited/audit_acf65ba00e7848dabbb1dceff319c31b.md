### Title
Unbounded Database Query via Zero `pageSize` in `PollingTopicListener.poll()` Causes OOM DoS

### Summary
When `PollingTopicListener` is active (listener type `POLL`), the `poll()` method computes `pageSize = Math.min(limit, maxPageSize)` where `limit = filter.getLimit() - context.getCount().get()`. When the count exactly equals the limit, `pageSize` becomes `0`. Because `TopicMessageFilter.hasLimit()` returns `false` for `limit=0`, `TopicMessageRepositoryCustomImpl.findByFilter()` skips `setMaxResults()` entirely and executes an unbounded SQL query, then materializes the entire result set into a Java `List` via `getResultList()`, causing OOM in the gRPC service.

### Finding Description

**Exact code path:**

`PollingTopicListener.poll()` — [1](#0-0) 

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())  // → 0 when count == limit
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());  // → 0
var newFilter = filter.toBuilder().limit(pageSize)...build();         // limit=0
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

`TopicMessageFilter.hasLimit()` — [2](#0-1) 

```java
public boolean hasLimit() {
    return limit > 0;  // false when limit == 0
}
```

`TopicMessageRepositoryCustomImpl.findByFilter()` — [3](#0-2) 

```java
if (filter.hasLimit()) {          // SKIPPED — hasLimit() is false for limit=0
    typedQuery.setMaxResults(...);
}
// ...
return typedQuery.getResultList().stream(); // loads ALL rows into memory
```

**Root cause:** The sentinel value `0` is overloaded: it means both "no limit requested" (in `TopicMessageFilter`) and "remaining budget is zero" (in `poll()`). When the polling budget is exhausted, `pageSize=0` is indistinguishable from "no limit" at the repository layer, bypassing `setMaxResults`.

**Exploit flow:**

1. Attacker subscribes to any active topic with `limit=N` (e.g., `limit=1`).
2. `TopicMessageServiceImpl.incomingMessages()` passes `newFilter` with `limit=N` to `topicListener.listen()`. [4](#0-3) 
3. `PollingTopicListener` creates a fresh `PollingContext` (count=0) and begins polling every 500 ms (default interval). [5](#0-4) 
4. N messages arrive; `doOnNext(context::onNext)` increments `PollingContext.count` to N. [6](#0-5) 
5. The current poll flux completes; `repeatWhen` schedules the next poll on the bounded-elastic scheduler after the interval — **before** the outer `.take(N)` cancel signal propagates back through the chain. [7](#0-6) 
6. Next `poll()` call: `limit = N - N = 0`, `pageSize = 0`, `findByFilter` runs without `setMaxResults`, returning every row for that topic from `startTime` onward.
7. `getResultList()` materializes the full result set into a `List<TopicMessage>` in the JVM heap. [8](#0-7) 

**Why the existing `.take()` guard is insufficient:**

`subscribeTopic()` applies `.take(filter.getLimit())` to the outer flux. [9](#0-8)  However, `repeatWhen` schedules the next poll asynchronously on a `Schedulers.boundedElastic()` thread after the current poll flux completes. The cancel signal from `.take()` must race against the already-scheduled next poll. With a 500 ms interval, the scheduled poll fires before cancellation propagates in practice.

### Impact Explanation
An attacker can force the gRPC service to execute an unbounded `SELECT` against the `topic_message` table (filtered only by `topic_id` and `consensusTimestamp >= startTime`) and load the entire result set into heap memory. A topic with millions of messages will exhaust JVM heap, crashing the gRPC service for all users. This is a remotely-triggered, unauthenticated Denial of Service. The attack is repeatable: each new subscription with `limit=N` on a high-volume topic can re-trigger it.

### Likelihood Explanation
The `POLL` listener type must be configured (non-default; default is `REDIS`). However, when `POLL` is active, any unauthenticated gRPC client can trigger this with `limit=1` on any topic that receives at least one message. No special knowledge or credentials are required. The attacker only needs to know a valid topic ID and wait for one message to arrive, making this trivially repeatable.

### Recommendation
Guard against `pageSize == 0` before calling `findByFilter`. The simplest fix is to return `Flux.empty()` immediately when the remaining budget is zero:

```java
private Flux<TopicMessage> poll(PollingContext context) {
    TopicMessageFilter filter = context.getFilter();
    TopicMessage last = context.getLast();
    int limit = filter.hasLimit()
            ? (int) (filter.getLimit() - context.getCount().get())
            : Integer.MAX_VALUE;
    if (limit <= 0) {
        return Flux.empty();  // budget exhausted; do not query
    }
    int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
    ...
}
```

Alternatively, `TopicMessageRepositoryCustomImpl.findByFilter()` should treat `limit == 0` as "return nothing" rather than "no limit":

```java
if (filter.getLimit() == 0) {
    return Stream.empty();
}
if (filter.hasLimit()) {
    typedQuery.setMaxResults((int) filter.getLimit());
}
```

### Proof of Concept

**Preconditions:** Mirror node configured with `hiero.mirror.grpc.listener.type=POLL`. A topic (e.g., `0.0.12345`) exists and receives at least 1 message.

**Steps:**

1. Open a gRPC `subscribeTopic` stream with:
   - `topicID = 0.0.12345`
   - `consensusStartTime = <epoch>`
   - `limit = 1`

2. Wait for one message to be delivered on the stream.

3. At the next poll interval (~500 ms), `PollingTopicListener.poll()` fires with `context.getCount() == 1 == filter.getLimit()`.

4. `pageSize = Math.min(1 - 1, 5000) = 0` → `findByFilter` called with `limit=0`.

5. `hasLimit()` returns `false` → `setMaxResults` not called → full table scan for that topic.

6. `getResultList()` loads all rows into heap → OOM / gRPC service crash observable via heap dump or JVM OOM error in logs.

**Repeatability:** Re-subscribe with `limit=1` after each crash to continuously DoS the service.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L47-47)
```java
                .doOnNext(context::onNext)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-61)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-60)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L115-120)
```java
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();

        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L30-30)
```java
    private Duration interval = Duration.ofMillis(500L);
```
