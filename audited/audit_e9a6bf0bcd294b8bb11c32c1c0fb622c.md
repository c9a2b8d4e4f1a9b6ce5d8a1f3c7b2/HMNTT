### Title
Unthrottled Retriever Silently Delivers Incomplete Records When User Limit Exceeds `maxPolls × maxPageSize`

### Summary
In `PollingTopicMessageRetriever`, the `isComplete()` method in unthrottled mode returns `true` only when `limitHit` (i.e., `total == filter.getLimit()`). However, the `RepeatSpec` that drives polling has a hard cap of `numRepeats = maxPolls` (default 12). When a user-supplied limit exceeds `maxPolls × maxPageSize` (12 × 5000 = 60,000), the `RepeatSpec` exhausts its repeat budget and emits `onComplete()` before `isComplete()` ever returns `true`, silently delivering fewer records than requested with no error signal to the client.

### Finding Description

**Exact code path:**

In `retrieve()`, the repeat predicate and repeat count are both passed to `RepeatSpec.create()`:

```java
// PollingTopicMessageRetriever.java, lines 51-55
return Flux.defer(() -> poll(context))
        .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                ...
``` [1](#0-0) 

In unthrottled mode, `numRepeats = maxPolls = 12` and `maxPageSize = 5000`:

```java
// lines 102-107
numRepeats = unthrottled.getMaxPolls();   // 12
maxPageSize = unthrottled.getMaxPageSize(); // 5000
``` [2](#0-1) 

`isComplete()` in unthrottled mode returns only `limitHit`:

```java
// lines 121-129
boolean isComplete() {
    boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();
    if (throttled) {
        return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
    }
    return limitHit;  // ← unthrottled: only true when total == limit
}
``` [3](#0-2) 

**Root cause:** `RepeatSpec.create(predicate, maxRepeats)` stops repeating when *either* the predicate returns `false` *or* `maxRepeats` is exhausted — whichever comes first. When `limit > 12 × 5000 = 60,000`, `isComplete()` never returns `true` (predicate stays `true`), but `RepeatSpec` exhausts its 12 repeats and terminates the Flux with `onComplete()`. No error is raised.

**Trigger path via safety check:**

In `TopicMessageServiceImpl.subscribeTopic()`, the safety check fires after 1 second if no data has arrived, and calls `retrieve(gapFilter, false)` (unthrottled) with the user's original filter — including the user-supplied limit:

```java
// TopicMessageServiceImpl.java, lines 67-70
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
``` [4](#0-3) 

`missingMessages(topicContext, null)` calls `retrieve(gapFilter, false)` where `gapFilter` carries the user's limit: [5](#0-4) 

**Why existing checks fail:**

- `flux.take(filter.getLimit())` at line 84 of `TopicMessageServiceImpl` only caps the total delivered — it does not guarantee that all records up to the limit are fetched.
- The sequence-number deduplication filter (`t.getSequenceNumber() > last.getSequenceNumber()`) skips duplicates but does not fill gaps.
- There is no error or warning emitted when `RepeatSpec` exhausts its budget without `isComplete()` returning `true`. [6](#0-5) 

### Impact Explanation

When the safety check triggers during a large message gap (e.g., importer was down), the unthrottled retriever silently stops after delivering at most 60,000 messages (12 × 5,000). Messages between position 60,001 and the first live message are permanently skipped. The client receives an `onComplete()` signal with no indication that records were omitted. Any downstream system relying on the topic stream for state reconstruction (e.g., a mirror node replicating consensus state) will have an incorrect, incomplete view. This falls directly within the stated scope of "Incorrect or missing records exported to mirror nodes."

### Likelihood Explanation

- **Precondition 1:** Any unprivileged gRPC client can set an arbitrarily large `limit` in `ConsensusTopicQuery` — no server-side cap is enforced on the filter's limit value.
- **Precondition 2:** The safety check fires automatically after 1 second whenever no data has arrived, which is a normal condition during initial subscription or importer downtime.
- **Precondition 3:** A gap larger than 60,000 messages is realistic during extended importer outages on high-throughput topics.
- The combination is reproducible and requires no special privileges. An attacker who knows the system's `maxPolls` and `maxPageSize` configuration can deliberately set `limit > maxPolls × maxPageSize` to guarantee the condition.

### Recommendation

In `isComplete()`, unthrottled mode must also detect poll exhaustion. The simplest fix is to mirror the throttled logic: treat a page smaller than `maxPageSize` as a completion signal in unthrottled mode as well, or track the poll count and signal completion (with an error or warning) when `numRepeats` is exhausted without `limitHit`. Concretely:

```java
boolean isComplete() {
    boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();
    // In both modes, a partial page means no more data exists
    return pageSize.get() < maxPageSize || limitHit;
}
```

Alternatively, emit an error (not `onComplete`) when the poll budget is exhausted without satisfying the limit, so callers can detect and handle the incomplete delivery.

### Proof of Concept

1. Start the mirror node gRPC service with default config (`maxPolls=12`, `maxPageSize=5000`).
2. Insert exactly 70,000 topic messages into the database for topic `0.0.1234` at timestamps in the past.
3. Subscribe via gRPC with `ConsensusTopicQuery { topicID: 0.0.1234, limit: 1000000 }`.
4. Ensure no live messages arrive for at least 1 second (so the safety check triggers).
5. Observe: the safety check calls `retrieve(gapFilter, false)` (unthrottled, `limit=1000000`).
6. After 12 polls × 5000 = 60,000 messages, `RepeatSpec` exhausts its budget.
7. `isComplete()` returns `false` (total=60,000 ≠ 1,000,000) but the stream emits `onComplete()`.
8. The client receives 60,000 messages and a clean completion signal — 10,000 messages are silently missing.
9. Confirm by counting received sequence numbers: gap between seq 60,001 and 70,000 is absent with no error.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-55)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L102-107)
```java
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L121-129)
```java
        boolean isComplete() {
            boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();

            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
            }

            return limitHit;
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L138-150)
```java
    private Flux<TopicMessage> missingMessages(TopicContext topicContext, @Nullable TopicMessage current) {
        final var last = topicContext.getLast();

        // Safety check triggered
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
        }
```
