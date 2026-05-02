After verifying every line reference against the actual source code, all claims are accurate. Here is the audit report.

---

Audit Report

## Title
Unthrottled Unlimited DB Polling via Unauthenticated gRPC Topic Subscription Safety Check

## Summary
Any unauthenticated client subscribing to a valid topic via the gRPC API triggers a one-shot safety check that invokes the unthrottled `PollingTopicMessageRetriever` with no query limit. Because `PollingContext.isComplete()` in unthrottled mode never returns `true` when no limit is set, the retriever unconditionally executes all 12 configured polls (up to 5,000 rows each) per subscription per reconnect cycle. With no enforced cap on concurrent subscribers or connections, an attacker can amplify database load proportionally to the number of open connections.

## Finding Description

**Safety check fires for every live subscription.**
`TopicMessageServiceImpl.subscribeTopic()` schedules a safety check for every subscription: [1](#0-0) 

`TopicContext.isComplete()` returns `false` whenever `filter.getEndTime() == null`, which is the common case for live subscribers: [2](#0-1) 

So the safety check fires after 1 second for every live subscription, not only when the importer is down.

**Safety check builds a no-limit filter and calls the unthrottled retriever.**
In `missingMessages()`, when `current == null` (the safety-check branch), the filter is rebuilt without adding any limit, then passed to the unthrottled retriever: [3](#0-2) 

**Unthrottled `PollingContext` is configured with fixed maximums.**
`RetrieverProperties.UnthrottledProperties` defaults are `maxPageSize = 5000`, `maxPolls = 12`, `pollingFrequency = 20ms`: [4](#0-3) 

These are applied in `PollingContext` when `throttled = false`: [5](#0-4) 

**`PollingContext.isComplete()` never returns `true` without a limit in unthrottled mode.**
For throttled mode, the retriever stops early when the last page is smaller than `maxPageSize` (indicating no more data). For unthrottled mode, it only stops when `limitHit`: [6](#0-5) 

Because `gapFilter` carries no limit, `filter.hasLimit()` is `false`, `limitHit` is always `false`, and `isComplete()` never returns `true`. The retriever therefore executes all 12 polls unconditionally — even if every poll returns zero rows — totalling up to **60,000 rows and 12 DB round-trips per safety-check invocation**.

**No enforced subscriber cap.**
`subscriberCount` is a Micrometer gauge only and is never checked against a maximum: [7](#0-6) [8](#0-7) 

`maxConcurrentCallsPerConnection = 5` limits calls per TCP connection but places no cap on the number of connections: [9](#0-8) 

## Impact Explanation
Each attacker-controlled subscription triggers 12 sequential database queries of up to 5,000 rows each within approximately 240 ms. With N open connections × 5 concurrent subscriptions per connection, the attacker generates 60N unthrottled DB queries per reconnect cycle. The database connection pool becomes saturated, causing legitimate subscriber queries and importer writes to queue or time out. This constitutes a resource-exhaustion denial-of-service against the mirror node's gRPC topic subscription service and any other component sharing the same database pool.

## Likelihood Explanation
The gRPC port (default 5600) is publicly reachable with no authentication. A single attacker machine can open hundreds of TCP connections. The attack requires only a standard gRPC client library and a known topic ID (topic IDs are public on-chain). The reconnect loop (subscribe → wait 1 s → safety check fires → disconnect → repeat) is trivially scriptable. The attack is fully repeatable, requires no special privileges, and produces a measurable, sustained DB load increase proportional to the number of connections the attacker maintains.

## Recommendation
1. **Fix `PollingContext.isComplete()` for unthrottled mode** to also return `true` when the last page returned fewer rows than `maxPageSize` (matching the throttled-mode logic). This ensures the retriever stops as soon as there is no more data, regardless of whether a limit was set.
2. **Add a limit to the safety-check filter** in `missingMessages()` when `current == null`, capping the number of rows the gap-recovery query can return.
3. **Enforce a maximum subscriber count** by checking `subscriberCount` against a configurable threshold in `subscribeTopic()` and rejecting new subscriptions when the limit is reached.
4. **Rate-limit reconnects per client IP** at the gRPC server layer to prevent rapid reconnect amplification.

## Proof of Concept
1. Open N TCP connections to the gRPC port (default 5600).
2. On each connection, open 5 concurrent `subscribeTopic` streams for any valid topic ID with no `endTime` and no `limit`.
3. After 1 second, each stream's safety check fires, calling `missingMessages(ctx, null)`, which invokes `topicMessageRetriever.retrieve(gapFilter, false)`.
4. The unthrottled retriever executes 12 polls × up to 5,000 rows each per stream.
5. Disconnect and immediately reconnect to repeat the cycle every ~1.5 seconds.
6. With N=100 connections, this generates 100 × 5 × 12 = **6,000 unthrottled DB queries per 1.5-second cycle**, saturating the connection pool and causing timeouts for legitimate traffic.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L89-90)
```java
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-149)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-206)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L36-47)
```java
    public static class UnthrottledProperties {

        @Min(1000)
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
