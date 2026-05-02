### Title
Unbounded Concurrent Throttled Subscriptions Exhaust Private `boundedElastic()` Scheduler and Database Connection Pool

### Summary
`PollingTopicMessageRetriever.retrieve()` creates a private `Schedulers.boundedElastic()` instance and, when `throttled=true`, sets `numRepeats=Long.MAX_VALUE` with no global cap on concurrent subscriptions. An unprivileged attacker can open many gRPC connections (each with up to 5 concurrent calls per `maxConcurrentCallsPerConnection`) and subscribe with `startTime=0` on a topic with large message history, causing the private scheduler's thread pool and the shared database connection pool to be saturated, degrading or blocking historical message delivery for all subscribers.

### Finding Description

**Code path:**

`TopicMessageServiceImpl.subscribeTopic()` always calls the retriever with `throttled=true`: [1](#0-0) 

Inside `PollingTopicMessageRetriever.retrieve()`, a private scheduler is created at construction time: [2](#0-1) 

When `throttled=true`, `PollingContext` sets `numRepeats=Long.MAX_VALUE` and `frequency=2s`: [3](#0-2) 

The repeat continues while `!context.isComplete()`. For throttled mode, `isComplete()` only returns `true` when the last page was smaller than `maxPageSize` (1000) or the limit is hit: [4](#0-3) 

With `startTime=0` on a topic with millions of messages, every poll returns a full page of 1000, so `isComplete()` stays `false` and polling continues until the 60-second timeout. Each poll executes a blocking JDBC call via `Flux.fromStream(topicMessageRepository.findByFilter(newFilter))`, occupying a thread from the private `boundedElastic()` pool for the duration of the query: [5](#0-4) 

**Root cause:** No global or per-client subscription count limit is enforced. The only per-connection limit is `maxConcurrentCallsPerConnection=5`: [6](#0-5) 

An attacker opens N connections × 5 calls each = 5N concurrent subscriptions. The `subscriberCount` field is a metric gauge only, never enforced as a ceiling: [7](#0-6) 

**Why the timeout is insufficient:** The default timeout is 60 seconds: [8](#0-7) 

The attacker simply reconnects immediately after each timeout, maintaining a continuous flood of polling tasks. With 2-second polling frequency and 60-second timeout, each subscription issues ~30 DB queries before expiring.

### Impact Explanation

1. **Private `boundedElastic()` scheduler saturation:** The private scheduler (default cap: `10 × availableProcessors()` threads) is shared across all subscriptions handled by this retriever instance. With hundreds of concurrent subscriptions each issuing blocking JDBC polls, the thread pool fills up. New poll tasks queue behind existing ones, causing all historical message delivery to stall — including for legitimate subscribers.

2. **Database connection pool exhaustion:** Each `findByFilter` call consumes a JDBC connection. With hundreds of concurrent polls firing every 2 seconds, the DB connection pool is exhausted, causing all DB-dependent operations (entity lookups, live message queries, safety checks) to block or fail with connection timeout errors.

3. **Cascading denial of service:** The `safetyCheck` in `TopicMessageServiceImpl` uses the shared `Schedulers.boundedElastic()` (a separate instance), so it is not directly starved by the private scheduler. However, DB pool exhaustion affects it indirectly. Live gossip delivery via `topicListener.listen()` is unaffected by the scheduler but is degraded by DB unavailability.

**Severity: High** — complete disruption of historical message retrieval and partial disruption of live delivery for all subscribers, achievable with no credentials.

### Likelihood Explanation

- **No authentication required:** Any gRPC client can subscribe to any topic.
- **Low resource cost for attacker:** Opening 200 TCP connections × 5 calls = 1000 concurrent subscriptions is trivial from a single machine or small botnet.
- **Continuously renewable:** After the 60-second timeout, the attacker reconnects. The attack is fully repeatable and automatable.
- **No rate limiting on subscription creation:** There is no token bucket, IP-based rate limit, or subscription count gate in the gRPC layer for `subscribeTopic`.

### Recommendation

1. **Enforce a global and per-IP subscription limit:** Add an atomic counter checked in `subscribeTopic()` before creating the subscription; reject with `RESOURCE_EXHAUSTED` when exceeded.
2. **Bound the private scheduler:** Replace `Schedulers.boundedElastic()` with a `Schedulers.newBoundedElastic(threadCap, queueSize, ...)` with an explicit, tuned cap and reject tasks when the queue is full.
3. **Require a minimum `startTime`:** Reject subscriptions with `startTime` older than a configurable threshold (e.g., 24 hours) to limit the volume of historical data a single subscription can trigger.
4. **Add per-IP connection limits** at the Netty/gRPC layer to complement `maxConcurrentCallsPerConnection`.
5. **Enforce a maximum page budget per subscription:** Track total pages polled and terminate after a configurable maximum, independent of the timeout.

### Proof of Concept

**Preconditions:**
- A valid topic ID exists with at least 100,000 messages in the mirror node database.
- The gRPC endpoint is reachable without authentication.

**Steps:**

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from google.protobuf.timestamp_pb2 import Timestamp

ENDPOINT = "mirror-node:5600"
TOPIC_ID = "<shard>.<realm>.<num>"
NUM_CONNECTIONS = 200
CALLS_PER_CONNECTION = 5  # matches maxConcurrentCallsPerConnection

def flood_subscribe(channel):
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    request = consensus_service_pb2.ConsensusTopicQuery(
        topicID=...,
        consensusStartTime=Timestamp(seconds=0, nanos=0),  # startTime=0
        # no limit, no endTime
    )
    try:
        for _ in stub.subscribeTopic(request):
            pass
    except Exception:
        pass

threads = []
for _ in range(NUM_CONNECTIONS):
    channel = grpc.insecure_channel(ENDPOINT)
    for _ in range(CALLS_PER_CONNECTION):
        t = threading.Thread(target=flood_subscribe, args=(channel,))
        t.start()
        threads.append(t)

# After ~10 seconds, legitimate subscribers experience stalled historical delivery
# and DB connection timeouts are observable in server logs.
```

**Expected result:** Server logs show DB connection pool exhaustion errors; legitimate `subscribeTopic` calls for historical messages stall or time out; the private `boundedElastic()` scheduler queue depth grows to its cap.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-90)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-41)
```java
        scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L77-78)
```java
        log.debug("Executing query: {}", newFilter);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L28-28)
```java
    private Duration timeout = Duration.ofSeconds(60L);
```
