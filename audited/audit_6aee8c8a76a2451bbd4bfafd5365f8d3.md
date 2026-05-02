### Title
Unbounded Concurrent gRPC Subscriptions Exhaust Shared `boundedElastic` Scheduler via `numRepeats=Long.MAX_VALUE` in Throttled Historical Retrieval

### Summary
Any unprivileged external caller of the `subscribeTopic` gRPC endpoint triggers `PollingTopicMessageRetriever.retrieve(filter, true)` with `throttled=true` hardcoded, which sets `numRepeats=Long.MAX_VALUE` and schedules polling tasks every 2 seconds on the shared `Schedulers.boundedElastic()` instance. Because there is no rate limiting or concurrent-subscription cap at the gRPC layer, an attacker can open arbitrarily many concurrent subscriptions, flooding the shared scheduler's task queue and starving legitimate subscribers of scheduler capacity.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` line 63 calls `topicMessageRetriever.retrieve(filter, true)` with `throttled=true` hardcoded. This reaches `PollingTopicMessageRetriever.retrieve()`.

Inside `PollingContext` constructor (lines 98–101):
```java
if (throttled) {
    numRepeats = Long.MAX_VALUE;          // line 99
    frequency = retrieverProperties.getPollingFrequency();  // default 2s
    maxPageSize = retrieverProperties.getMaxPageSize();     // default 1000
}
```

The `retrieve()` method (lines 51–55) schedules repeat polling on the **shared** `Schedulers.boundedElastic()` singleton:
```java
return Flux.defer(() -> poll(context))
    .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
        .withFixedDelay(context.getFrequency())
        .withScheduler(scheduler))   // shared boundedElastic
```

The scheduler field is initialized at line 41: `scheduler = Schedulers.boundedElastic()` — this returns the **shared** Reactor singleton, not a per-instance pool.

**Early-termination condition** (`isComplete()`, lines 124–125):
```java
if (throttled) {
    return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
}
```
For a topic with a continuous stream of messages (or any topic where the last page is full), `isComplete()` never returns `true` during the subscription lifetime, so the `Long.MAX_VALUE` repeat loop runs until the timeout fires.

**The 60-second timeout** (line 59: `.timeout(retrieverProperties.getTimeout(), scheduler)`) is the primary mitigation. It terminates each subscription after 60 seconds. However:
- The attacker reconnects immediately after each timeout, maintaining a constant pool of active subscriptions.
- The `retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))` at line 58 is chained *inside* the timeout, so transient DB errors cause rapid retry bursts within the 60-second window, multiplying scheduler task submissions per subscription.
- No rate limiting, no per-IP connection cap, and no maximum subscriber count check exists anywhere in the gRPC controller or service layer.

**Root cause:** `numRepeats=Long.MAX_VALUE` combined with no concurrent-subscription limit and a shared scheduler means N concurrent subscriptions generate N×(60s/2s) = N×30 scheduler tasks per 60-second window. The `boundedElastic` scheduler's default task queue is 100,000 entries; at ~3,334 concurrent subscriptions the queue saturates, causing `RejectedExecutionException` for all subsequent scheduling attempts, including those from legitimate subscribers.

### Impact Explanation
When the shared `boundedElastic` scheduler queue is saturated, all Reactor pipelines that depend on it — including the `safetyCheck` flux in `TopicMessageServiceImpl` (line 70, also using `Schedulers.boundedElastic()`) and the timeout scheduling itself (line 59 passes the same `scheduler`) — fail to schedule tasks. Legitimate subscribers stop receiving messages and eventually time out. This is a full denial-of-service on the mirror node's gRPC topic subscription service for all users, not just the attacker.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is unauthenticated and publicly accessible. Opening thousands of concurrent gRPC streams is trivially achievable with standard tooling (e.g., `grpcurl` in a loop, or a small script using any gRPC client library). The attacker does not need any special knowledge of the topic IDs — any valid or even invalid topic ID triggers the historical retrieval path. The attack is repeatable and stateless from the attacker's perspective.

### Recommendation
1. **Add a per-IP or global concurrent-subscription cap** in `ConsensusController` or `TopicMessageServiceImpl`, rejecting new subscriptions with `RESOURCE_EXHAUSTED` when the limit is exceeded.
2. **Use a dedicated, bounded scheduler** in `PollingTopicMessageRetriever` instead of the shared `Schedulers.boundedElastic()` singleton, so retriever exhaustion cannot affect other Reactor pipelines.
3. **Cap `numRepeats` for throttled mode** to a finite value (e.g., `timeout / pollingFrequency + 1`) rather than `Long.MAX_VALUE`, relying on the timeout as the sole termination guard.
4. **Add gRPC server-side interceptor** for rate limiting (e.g., using a token bucket per client IP).

### Proof of Concept

```bash
# Open 4000 concurrent gRPC subscriptions to a high-traffic topic
# (replace <mirror-node-host> and topic ID as appropriate)
for i in $(seq 1 4000); do
  grpcurl -plaintext \
    -d '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Each subscription triggers retrieve(filter, true) → numRepeats=Long.MAX_VALUE
# → schedules a task on Schedulers.boundedElastic() every ~2s
# → 4000 × 30 tasks/60s = 120,000 tasks, exceeding the 100,000-entry queue
# → RejectedExecutionException on the shared scheduler
# → legitimate subscribers stop receiving messages / time out
```