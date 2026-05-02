### Title
Unthrottled Unlimited DB Polling via Unauthenticated gRPC Topic Subscription Safety Check

### Summary
Any unauthenticated client can subscribe to a valid topic via the gRPC API and trigger the safety-check branch of `missingMessages()`, which invokes `topicMessageRetriever.retrieve(gapFilter, false)` in unthrottled mode with no query limit. Because there is no enforced cap on the number of concurrent subscribers or connections, an attacker can open arbitrarily many connections and force up to 12 back-to-back database polls of 5,000 rows each per subscription per reconnect cycle, saturating the database connection pool and starving legitimate subscribers.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.subscribeTopic()` schedules a one-shot safety check for every subscription:

```java
// TopicMessageServiceImpl.java lines 67-70
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
```

`topicContext.isComplete()` returns `false` for any subscription without an `endTime` (lines 203-215), so the safety check always fires after 1 second.

`missingMessages()` with `current == null` (lines 142-150) builds a filter with **no limit** and calls the unthrottled retriever:

```java
var gapFilter = topicContext.getFilter().toBuilder().startTime(startTime).build();
return topicMessageRetriever.retrieve(gapFilter, false);   // line 149 — unthrottled, no limit
```

Inside `PollingTopicMessageRetriever.retrieve()` (lines 44-63), the unthrottled `PollingContext` is configured with:
- `maxPageSize = 5000`
- `numRepeats = maxPolls = 12`
- `pollingFrequency = 20ms`

`PollingContext.isComplete()` for unthrottled mode (lines 121-128) only returns `true` when `limitHit`:

```java
return limitHit;   // line 128 — limitHit = filter.hasLimit() && filter.getLimit() == total.get()
```

Because `gapFilter` carries no limit, `filter.hasLimit()` is `false`, `limitHit` is always `false`, and `isComplete()` never returns `true`. The retriever therefore executes all 12 polls unconditionally, each fetching up to 5,000 rows, totalling up to **60,000 rows and 12 DB round-trips per safety-check invocation**.

**Failed assumption:** The design assumes the safety check fires rarely (only when the importer is down). It fires for every subscription that lacks an `endTime`, which is the common case for live subscribers.

**No enforced subscriber limit:** `subscriberCount` (lines 48, 89-90) is a Micrometer gauge only — it is never checked against a maximum. `maxConcurrentCallsPerConnection = 5` (NettyProperties line 14) limits calls per TCP connection but places no cap on the number of connections.

### Impact Explanation

Each attacker-controlled subscription triggers 12 sequential database queries of up to 5,000 rows each within ~240 ms. With N open connections × 5 concurrent subscriptions per connection, the attacker generates 60N unthrottled DB queries per reconnect cycle. The database connection pool (default `statementTimeout = 10,000 ms`) becomes saturated, causing legitimate subscriber queries and importer writes to queue or time out. This constitutes a full denial-of-service against the mirror node's gRPC topic subscription service and any other component sharing the same database pool, with no ability for the server to distinguish attacker traffic from legitimate traffic.

### Likelihood Explanation

The gRPC port (default 5600) is publicly reachable with no authentication. A single attacker machine can open hundreds of TCP connections. The reconnect loop (subscribe → wait 1 s → safety check fires → disconnect → repeat) requires only a standard gRPC client library and a known topic ID (topic IDs are public on-chain). The attack is fully repeatable, requires no special privileges, and produces a measurable, sustained DB load increase proportional to the number of connections the attacker maintains.

### Recommendation

1. **Add a limit to the safety-check gap filter.** At line 146-147 of `TopicMessageServiceImpl.java`, propagate the original filter's limit (or a configured maximum) into `gapFilter` so `PollingContext.isComplete()` can terminate early:
   ```java
   var gapFilter = topicContext.getFilter().toBuilder()
           .startTime(startTime)
           .limit(retrieverProperties.getUnthrottled().getMaxPageSize()) // cap the safety-check query
           .build();
   ```

2. **Enforce a global subscriber ceiling.** Check `subscriberCount` before accepting a new subscription in `subscribeTopic()` and return `RESOURCE_EXHAUSTED` if the limit is exceeded.

3. **Enforce a per-IP or per-connection subscription rate limit** at the Netty/gRPC interceptor layer to prevent rapid reconnect cycling.

4. **Consider making the safety check throttled** (`retrieve(gapFilter, true)`) so it respects `pollingFrequency = 2s` and `maxPageSize = 1000` instead of the aggressive unthrottled parameters.

### Proof of Concept

```
Preconditions:
  - Mirror node gRPC port 5600 is reachable.
  - At least one valid topic ID exists (e.g., 0.0.1234).
  - No authentication is configured.

Steps:
  1. Open 200 TCP connections to grpc://mirror-node:5600.
  2. On each connection, issue 5 concurrent SubscribeTopic RPCs for topic 0.0.1234
     with startTime = 0 and no endTime/limit.
  3. Wait 1 second.
  4. Observe: each of the 1,000 subscriptions fires the safety check, issuing
     12 × 5,000-row queries = 12,000 DB queries within ~240 ms.
  5. Disconnect all connections and immediately reconnect (repeat from step 2).

Expected result:
  - Database CPU/IO spikes to saturation.
  - Legitimate subscribers receive no messages or timeout errors.
  - Mirror node logs show thousands of "Safety check triggering gap recovery query" entries.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L102-107)
```java
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
