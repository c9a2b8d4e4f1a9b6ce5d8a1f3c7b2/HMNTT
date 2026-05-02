All code paths have been verified against the actual source. Here is the audit result:

---

Audit Report

## Title
Unbounded Heap Allocation via Unthrottled Safety-Check Poll on Open-Ended Topic Subscription

## Summary
An unprivileged gRPC client can subscribe to any topic with `startTime=0` and no `endTime`, causing a deterministic safety-check path in `TopicMessageServiceImpl` to unconditionally trigger an unthrottled `retrieve()` call after 1 second. Each such call materializes up to 5,000 `TopicMessage` objects per poll, repeated up to 13 times (12 repeats + initial), totalling up to 65,000 heap-allocated objects per subscription. With no per-user or global subscription cap enforced, many concurrent connections multiply this heap pressure linearly, causing GC pauses that degrade all gRPC I/O operations and, in extreme cases, an `OutOfMemoryError`.

## Finding Description

**Code path 1 — safety check unconditionally fires for every open-ended subscription:**

In `TopicMessageServiceImpl.subscribeTopic()`, a safety-check `Mono` fires after 1 second:

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
``` [1](#0-0) 

`topicContext.isComplete()` returns `false` unconditionally when `filter.getEndTime() == null`:

```java
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;
    }
    ...
}
``` [2](#0-1) 

Therefore, every subscription without an `endTime` passes the `.filter()` check and `missingMessages(topicContext, null)` is called.

**Code path 2 — `missingMessages()` calls unthrottled retrieval:**

When `current == null` (the safety-check branch), `missingMessages()` calls:

```java
return topicMessageRetriever.retrieve(gapFilter, false);  // throttled=false
``` [3](#0-2) 

**Code path 3 — unthrottled retrieval polls up to 13 times with 5,000-row pages:**

`PollingContext` for unthrottled mode reads from `RetrieverProperties.UnthrottledProperties`: [4](#0-3) 

Default values are `maxPageSize=5000`, `maxPolls=12`, `pollingFrequency=20ms`: [5](#0-4) 

`PollingContext.isComplete()` for unthrottled returns only `limitHit`, which is `false` when no limit is set:

```java
return limitHit;   // false when filter has no limit
``` [6](#0-5) 

So the retriever polls `maxPolls + 1 = 13` times (confirmed by the test comment: *"the retriever should query the db for up to MaxPolls + 1 times when no limit is set"*). [7](#0-6) 

**Code path 4 — each poll fully materializes the page into heap:**

`TopicMessageRepositoryCustomImpl.findByFilter()` calls `getResultList()` before returning a stream:

```java
return typedQuery.getResultList().stream();
``` [8](#0-7) 

The comment in the source confirms this is intentional (`getResultStream()`'s cursor doesn't work with reactive streams), but it means the entire page is allocated as a `List<TopicMessage>` before any element is consumed.

**No subscription count enforcement:**

`subscriberCount` is a Micrometer gauge only — it is never checked against a maximum: [9](#0-8) 

`maxConcurrentCallsPerConnection = 5` limits calls per TCP connection but an attacker opens arbitrarily many connections. [10](#0-9) 

## Impact Explanation

Each open-ended subscription triggers one unthrottled retrieval that allocates up to 13 × 5,000 = **65,000 `TopicMessage` objects** into heap. Each `TopicMessage` carries a binary payload (up to 6 KiB per the proto spec), so worst-case heap pressure per subscription is on the order of hundreds of MB. With N concurrent subscriptions, heap usage scales linearly. Sustained heap pressure causes stop-the-world GC pauses (G1/ZGC) that stall all gRPC I/O threads, degrading or completely blocking message delivery for all subscribers on the node. In extreme cases, `OutOfMemoryError` terminates the JVM. No funds are at direct risk; the impact is Denial-of-Service against the gRPC network layer.

## Likelihood Explanation

The attack requires only a valid gRPC client — no credentials, no privileged account. The attacker needs a `topicId` with a large message history; public topics on Hedera mainnet have millions of messages and their IDs are publicly discoverable. Opening many TCP connections is trivial. The safety-check trigger is deterministic (fires after exactly 1 second on every subscription without `endTime`), making the exploit fully repeatable and scriptable.

## Recommendation

1. **Cap concurrent subscriptions globally:** Check `subscriberCount` against a configurable maximum in `subscribeTopic()` and reject new subscriptions with an appropriate gRPC status (`RESOURCE_EXHAUSTED`) when the cap is reached.
2. **Bound the unthrottled safety-check retrieval:** When the safety-check path in `missingMessages()` is triggered and no `endTime` is set, apply an explicit `endTime` (e.g., `Instant.now()`) to the `gapFilter` so the unthrottled retrieval is bounded in scope rather than scanning the entire topic history.
3. **Limit `maxPolls` for safety-check context:** Consider passing a separate, more conservative `PollingContext` configuration for safety-check retrievals (e.g., `maxPolls=1` or `maxPolls=2`) rather than reusing the full unthrottled defaults.
4. **Stream results lazily:** Replace `getResultList().stream()` with a cursor-based or paginated approach that does not materialize the full page into a `List` before returning, reducing peak heap allocation per poll.

## Proof of Concept

```python
import grpc
import hapi.mirror.api.proto.consensus_service_pb2 as cs
import hapi.mirror.api.proto.consensus_service_pb2_grpc as cs_grpc
import threading, time

MIRROR_NODE = "mainnet-public.mirrornode.hedera.com:443"
TOPIC_ID = 0  # shard
TOPIC_NUM = 96  # a high-volume public topic (e.g., 0.0.96)

def open_subscription():
    channel = grpc.secure_channel(MIRROR_NODE, grpc.ssl_channel_credentials())
    stub = cs_grpc.ConsensusServiceStub(channel)
    req = cs.ConsensusTopicQuery(
        topicID=...,   # set to TOPIC_NUM
        consensusStartTime=...,  # epoch 0 (startTime=0)
        # no consensusEndTime → isComplete() always false
        # no limit → unthrottled isComplete() always false
    )
    try:
        for _ in stub.subscribeTopic(req):
            pass  # consume slowly or not at all
    except Exception:
        pass

# Open N concurrent connections; each triggers the safety-check after 1s,
# allocating up to 65,000 TopicMessage objects per subscription into heap.
threads = [threading.Thread(target=open_subscription) for _ in range(200)]
for t in threads:
    t.start()
time.sleep(5)
# At this point, heap pressure from safety-check retrievals is sustained.
```

Each of the 200 threads triggers one unthrottled retrieval after 1 second, each polling up to 13 times × 5,000 rows = 65,000 `TopicMessage` objects materialized into heap simultaneously.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-55)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-215)
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

**File:** grpc/src/test/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetrieverTest.java (L260-262)
```java
        // in unthrottled mode, the retriever should query the db for up to MaxPolls + 1 times when no limit is set,
        // regardless of whether a db query returns less rows than MaxPageSize
        StepVerifier.withVirtualTime(() ->
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-60)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** docs/configuration.md (L424-424)
```markdown
| `hiero.mirror.grpc.netty.maxConcurrentCallsPerConnection`  | 5                | The maximum number of concurrent calls permitted for each incoming connection                             |
```
