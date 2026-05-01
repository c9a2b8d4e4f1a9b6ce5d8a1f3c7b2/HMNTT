### Title
Unbounded Concurrent gRPC Subscriptions Exhaust Shared `boundedElastic()` Scheduler via Throttled Historical Retrieval (No Auth Required)

### Summary
`PollingTopicMessageRetriever.retrieve()` unconditionally sets `numRepeats = Long.MAX_VALUE` for every `throttled=true` subscription and schedules all repeat delays and timeout checks on a single shared `Schedulers.boundedElastic()` instance. There is no global cap on concurrent subscriptions — only a per-TCP-connection limit of 5 — so an unauthenticated attacker opening many connections can saturate the shared thread pool, causing all legitimate subscribers' polls to queue indefinitely and their 60-second timeouts to fire, permanently starving topic message delivery.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` (line 63) always calls:
```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);  // throttled=true, always
```

Inside `PollingTopicMessageRetriever.retrieve()` (lines 45–63), when `throttled=true`:

```java
// PollingContext constructor, line 98-101
if (throttled) {
    numRepeats = Long.MAX_VALUE;          // unbounded repeat count
    frequency = retrieverProperties.getPollingFrequency();  // default 2s
    maxPageSize = retrieverProperties.getMaxPageSize();     // default 1000
}
```

The flux is assembled as:
```java
return Flux.defer(() -> poll(context))
    .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
        .withFixedDelay(context.getFrequency())
        .withScheduler(scheduler))          // shared boundedElastic()
    .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))  // also infinite retry
    .timeout(retrieverProperties.getTimeout(), scheduler)             // also on same scheduler
```

The `scheduler` field is set at construction time (line 41):
```java
scheduler = Schedulers.boundedElastic();
```

`Schedulers.boundedElastic()` returns the **global shared singleton** scheduler (Reactor's static factory). Every subscription — historical retrieval, safety check (`TopicMessageServiceImpl` line 70), and timeout — competes for the same bounded thread pool.

**Root cause — failed assumption in `isComplete()`:**

```java
boolean isComplete() {
    boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();
    if (throttled) {
        return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
    }
    return limitHit;
}
```

`pageSize` is reset to 0 at the start of every poll (line 73: `context.getPageSize().set(0L)`). For a topic with ≥ 1000 historical messages (the default `maxPageSize`), the first poll fills a full page, `pageSize = 1000`, `isComplete()` returns `false`, and the subscription repeats. This continues until the retriever catches up — which for a topic with millions of messages takes thousands of polls over many minutes. For a live topic with a sustained message rate ≥ 500 msg/s, `isComplete()` **never** returns `true`.

**Exploit flow:**

1. Attacker opens *N* TCP connections to port 5600 (no authentication required).
2. Each connection issues 5 concurrent `subscribeTopic` RPCs (the per-connection cap, `maxConcurrentCallsPerConnection = 5`).
3. Each subscription targets a topic with ≥ 1000 historical messages (or any live high-throughput topic).
4. Each subscription schedules a 2-second repeat task on the shared `boundedElastic()` scheduler.
5. With *N* × 5 concurrent subscriptions all polling simultaneously, the DB connection pool is exhausted; queries block waiting for a JDBC connection.
6. `boundedElastic()` worker threads are held while blocked on DB acquisition, exhausting the thread pool (default cap: `10 × availableProcessors()`).
7. Legitimate subscribers' next poll tasks are queued but never dequeued.
8. No messages are emitted to legitimate subscribers for > 60 seconds → `.timeout(retrieverProperties.getTimeout(), scheduler)` fires → legitimate subscriptions are terminated with `TimeoutException`.

**Why existing checks fail:**

| Check | Why insufficient |
|---|---|
| `maxConcurrentCallsPerConnection = 5` | Per-connection only; attacker opens *N* connections, total subscriptions = 5*N*, unbounded |
| `timeout = 60s` | Resets on every emitted message; attacker's subscriptions on active topics never time out |
| `isComplete()` early exit | Only triggers when last page < 1000; never triggers for full-page topics |
| `subscriberCount` gauge (line 48–55) | Metrics only, no enforcement |
| `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` | Actively works against mitigation — retries indefinitely on any error |

### Impact Explanation

Complete denial-of-service for the gRPC `subscribeTopic` endpoint. Legitimate subscribers receive no topic messages and are terminated by timeout. Because the shared `boundedElastic()` scheduler is also used by `TopicMessageServiceImpl`'s safety check (`subscribeOn(Schedulers.boundedElastic())`, line 70) and `pastEndTime` repeat loop (line 129), the starvation affects all reactive pipelines sharing that scheduler, not just the retriever. This directly prevents gossip of topic messages from being delivered to any subscriber — the core function of the service.

### Likelihood Explanation

No authentication or special privilege is required. The attacker needs only network access to port 5600 and the ability to open many TCP connections — achievable from a single machine with standard tooling (e.g., `grpcurl` in a loop, or a custom gRPC client). The per-connection limit of 5 is trivially bypassed by opening more connections. The attack is repeatable and self-sustaining: once the scheduler is saturated, new legitimate connections also fail, and the attacker's subscriptions on active topics auto-renew via the `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` chain.

### Recommendation

1. **Enforce a global concurrent-subscription cap** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add a per-IP or per-connection subscription limit** at the Netty/gRPC interceptor layer.
3. **Use a dedicated, size-limited scheduler** for `PollingTopicMessageRetriever` instead of the global `Schedulers.boundedElastic()`, so retriever exhaustion cannot starve other reactive pipelines.
4. **Cap `numRepeats`** for throttled subscriptions to a finite, configurable value (e.g., aligned with `retrieverProperties.getTimeout()`), rather than `Long.MAX_VALUE`.
5. **Remove or bound `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))`** — infinite retry amplifies the resource hold.

### Proof of Concept

```bash
# Prerequisites: grpcurl installed, topic 0.0.12345 exists with >= 1000 messages
# Step 1: Open 200 connections × 5 subscriptions = 1000 concurrent throttled retrievals
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d '{
      "topicID": {"topicNum": 12345},
      "consensusStartTime": {"seconds": 0}
    }' <grpc-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    > /dev/null 2>&1 &
  done
done

# Step 2: Observe that legitimate subscribers now receive no messages
# and are terminated after 60 seconds with DEADLINE_EXCEEDED / timeout.
grpcurl -plaintext -d '{
  "topicID": {"topicNum": 12345},
  "consensusStartTime": {"seconds": 0}
}' <grpc-host>:5600 \
com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected: no messages received, connection times out after ~60s
```

The exact connection count needed depends on `availableProcessors()` and DB pool size; on a typical 4-core pod with a 10-connection DB pool, ~50–100 concurrent subscriptions to a high-message-rate topic is sufficient to trigger observable starvation.