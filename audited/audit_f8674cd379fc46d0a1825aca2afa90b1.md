### Title
Unbounded Database Query via Safety Check Path in `missingMessages()` for Open-Ended Subscriptions

### Summary
Any unprivileged user can subscribe to a valid topic with no `endTime` and no `limit`, causing the safety check in `subscribeTopic()` to unconditionally fire after 1 second and invoke `missingMessages(topicContext, null)`. The resulting `gapFilter` inherits the original filter's null `endTime` and zero `limit`, triggering `topicMessageRetriever.retrieve(gapFilter, false)` — an unthrottled, unbounded database scan from `startTime` to the present. Multiple concurrent subscriptions multiply the impact linearly.

### Finding Description

**Exact code path:**

In `subscribeTopic()` (lines 67–70), the safety check is unconditionally scheduled:

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
``` [1](#0-0) 

The guard `!topicContext.isComplete()` is evaluated via `isComplete()` (lines 203–214):

```java
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;  // always false for open-ended subscriptions
    }
    ...
}
``` [2](#0-1) 

For any subscription without an `endTime`, `isComplete()` always returns `false`, so the safety check **always fires** after 1 second.

Inside `missingMessages()`, the `current == null` branch (lines 142–150) builds `gapFilter` by copying the original filter and only overriding `startTime`:

```java
if (current == null) {
    long startTime = last != null
            ? last.getConsensusTimestamp() + 1
            : topicContext.getFilter().getStartTime();
    var gapFilter =
            topicContext.getFilter().toBuilder().startTime(startTime).build();
    return topicMessageRetriever.retrieve(gapFilter, false);
}
``` [3](#0-2) 

**Root cause:** `gapFilter` inherits the original filter's `endTime` (null) and `limit` (0 = no limit). The call `retrieve(gapFilter, false)` passes `throttled=false`, bypassing any rate-limiting the retriever applies in the normal historical path (`retrieve(filter, true)` at line 63). [4](#0-3) 

**Failed assumption:** The safety check assumes it will only be reached when there is a genuine gap (importer was down). In reality, it fires for every open-ended subscription after 1 second, regardless of whether any gap exists.

**Why the deduplication filter does not help:** The sequence-number deduplication at lines 74–77 filters output to the subscriber, but the underlying database query is still fully executed, consuming DB I/O and memory. [5](#0-4) 

**`TopicMessageFilter` validation does not constrain this:** `isValidStartTime()` only requires `startTime <= now()`, allowing any historical timestamp. `isValidEndTime()` explicitly permits `endTime == null`. [6](#0-5) 

### Impact Explanation
An attacker with no privileges beyond knowing a valid topic ID can trigger an unthrottled full-table scan of the `topic_message` table from an arbitrarily old `startTime` to the present. On a busy network with millions of messages, this is a multi-gigabyte result set per subscription. Opening N concurrent subscriptions issues N such queries simultaneously, causing database CPU/memory exhaustion and degrading service for all users (DoS). There is no per-user connection cap visible in `GrpcProperties` that would prevent this. [7](#0-6) 

### Likelihood Explanation
The attack requires only a valid gRPC client and a known topic ID (topic IDs are public on the Hedera network). No authentication, no special role, no prior knowledge of internal state is needed. The 1-second trigger is deterministic and reliable. The attack is trivially scriptable and repeatable: open connections in a loop, each fires the safety check after exactly 1 second. This is a realistic, low-skill DoS.

### Recommendation

1. **Set an explicit `endTime` on `gapFilter`** in the `current == null` branch, capping the scan to the current wall-clock time:
   ```java
   var gapFilter = topicContext.getFilter().toBuilder()
           .startTime(startTime)
           .endTime(DomainUtils.now())   // add this
           .build();
   ```
2. **Use `throttled=true`** for the safety-check retrieve call, consistent with the initial historical retrieval.
3. **Guard the safety check more precisely**: only fire it if `topicContext.getLast() == null` AND the historical retrieval has already completed, not unconditionally after 1 second.
4. **Enforce a maximum result-set size** in the retriever when `endTime` is null, regardless of the `throttled` flag.

### Proof of Concept

**Preconditions:** Mirror node gRPC endpoint is reachable; at least one valid topic ID exists (e.g., `0.0.1234`).

**Steps:**

1. Open a `subscribeTopic` gRPC stream with:
   - `topicID = 0.0.1234`
   - `consensusStartTime` = genesis (e.g., `0` nanoseconds)
   - No `consensusEndTime`
   - No `limit`

2. Wait 1 second without sending any messages to the topic (or even if messages exist).

3. After 1 second, `isComplete()` returns `false` (no `endTime`), the safety check fires, `missingMessages(topicContext, null)` is called, and `retrieve(gapFilter, false)` executes an unthrottled query: `SELECT * FROM topic_message WHERE topic_id = 1234 AND consensus_timestamp >= 0` with no upper bound.

4. Repeat step 1 in a loop with 100 concurrent connections. 100 simultaneous unbounded scans are issued to the database after 1 second.

**Observable result:** Database CPU spikes to 100%, query latency for all other users increases, and the mirror node may become unresponsive.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L74-77)
```java
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-150)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-214)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }

            if (filter.getEndTime() < startTime) {
                return true;
            }

            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-51)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L17-30)
```java
public class GrpcProperties {

    private boolean checkTopicExists = true;

    @NotNull
    private Duration endTimeInterval = Duration.ofSeconds(30);

    @Min(1)
    private int entityCacheSize = 50_000;

    @NotNull
    @Valid
    private NettyProperties netty = new NettyProperties();
}
```
