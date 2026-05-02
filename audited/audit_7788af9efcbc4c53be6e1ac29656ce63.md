### Title
Unbounded Throttled Polling Subscriptions Enable DB Exhaustion via Unauthenticated Long-Lived Connections

### Summary
The `retrieve()` method in `PollingTopicMessageRetriever` sets `numRepeats = Long.MAX_VALUE` when `throttled=true`, with only an idle-based (not wall-clock) timeout as a termination guard. Combined with the absence of per-IP connection limits (only a per-TCP-connection stream cap of 5), an unauthenticated attacker can open arbitrarily many connections, each carrying 5 indefinitely-polling subscriptions, saturating the database with concurrent `findByFilter` queries and starving legitimate gossip subscribers.

### Finding Description

**Code path:**

In `PollingTopicMessageRetriever.retrieve()` (lines 45–63), when `throttled=true` the `PollingContext` constructor executes:

```java
// line 99
numRepeats = Long.MAX_VALUE;
// line 100
frequency = retrieverProperties.getPollingFrequency();   // default 2 s
// line 101
maxPageSize = retrieverProperties.getMaxPageSize();       // default 1000
``` [1](#0-0) 

The repeat loop is:
```java
.repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
        .withFixedDelay(context.getFrequency()) ...)
``` [2](#0-1) 

The only termination guards are:

1. **`isComplete()`** — for `throttled=true`, returns `true` only when the last poll returned fewer than `maxPageSize` messages or the limit is hit. On a high-traffic topic (>1000 msgs per 2 s), this never fires during the historical phase. [3](#0-2) 

2. **`.timeout(retrieverProperties.getTimeout(), scheduler)`** — default 60 s. This is Reactor's **per-element idle timeout**, not a wall-clock subscription duration. As long as any message is emitted within 60 s, the timeout never fires. [4](#0-3) 

**Root cause — failed assumption:** The design assumes `isComplete()` will eventually return `true` (retriever catches up to "now"), but on a continuously high-traffic topic with an old `startTime`, the retriever never catches up within a practical window, keeping `numRepeats = Long.MAX_VALUE` active indefinitely. Even after the historical phase ends, the live subscription in `TopicMessageServiceImpl.subscribeTopic()` has no wall-clock duration limit at all. [5](#0-4) 

**Connection limit bypass:** The only concurrency guard is `maxConcurrentCallsPerConnection = 5` (Netty layer), which limits streams per TCP connection but places no cap on the number of TCP connections from a single IP. [6](#0-5) 

Each poll issues a direct DB query:
```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
``` [7](#0-6) 

### Impact Explanation
With `C` TCP connections × 5 streams each, the attacker generates `5C` DB queries every 2 seconds (the default `pollingFrequency`). At modest scale (e.g., 200 connections = 1000 concurrent subscriptions), this produces 500 DB queries/second from the attacker alone, exhausting the DB connection pool and starving legitimate gossip queries. The `subscriberCount` gauge tracks active subscribers but enforces no ceiling. [8](#0-7) 

### Likelihood Explanation
- **No authentication required** — `subscribeTopic` is open to any gRPC client.
- **No IP-level rate limiting** in the codebase; only per-connection stream limits.
- **Precondition**: attacker needs one valid `topicId` (enumerable or publicly known) and a `startTime` set far in the past to keep the historical phase alive.
- **Repeatability**: after a 60 s idle timeout disconnects a stream, the client immediately reconnects — the gRPC SDK retries automatically.
- A single commodity machine with a standard gRPC client library can open hundreds of TCP connections.

### Recommendation
1. **Add a wall-clock maximum subscription duration** enforced server-side (e.g., `maxSubscriptionDuration` property), terminating any subscription older than the configured limit regardless of message flow.
2. **Enforce per-IP or per-authenticated-identity connection limits** at the Netty/load-balancer layer, not just per-connection stream limits.
3. **Cap `numRepeats` for throttled subscriptions** to a finite value tied to a configurable maximum historical catch-up window, rather than `Long.MAX_VALUE`.
4. **Add a global concurrent-subscription ceiling** (not just a metric gauge) that rejects new subscriptions when the server is saturated.

### Proof of Concept
```
Preconditions:
  - Mirror node gRPC port (default 5600) reachable
  - Any valid topicId (e.g., obtained from REST API /api/v1/topics)

Steps:
1. Write a script that opens N TCP connections to the gRPC endpoint.
2. On each connection, open 5 concurrent subscribeTopic streams:
     ConsensusTopicQuery {
       topicID: <valid_topic_id>,
       consensusStartTime: <timestamp 30 days ago>,
       // no consensusEndTime, no limit
     }
3. Each stream triggers retrieve(filter, throttled=true) with numRepeats=Long.MAX_VALUE,
   polling the DB every 2 s.
4. With N=200 connections: 1000 concurrent DB queries every 2 s.
5. Observe: legitimate subscribers receive DEADLINE_EXCEEDED or connection errors
   as the DB connection pool is exhausted.
6. The attack sustains itself; if the idle timeout fires (60 s of no messages),
   the client reconnects immediately.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-55)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L59-59)
```java
                .timeout(retrieverProperties.getTimeout(), scheduler)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L78-78)
```java
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L98-101)
```java
            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-64)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
