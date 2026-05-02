### Title
Unbounded Concurrent Historical Subscriptions Cause Heap Pressure via Per-Poll Page Allocation

### Summary
An unprivileged gRPC client can open arbitrarily many `subscribeTopic` streams with `limit=0` (no limit) and a historical `startTime`, causing `PollingTopicMessageRetriever` to repeatedly load up to `maxPageSize` rows per poll per subscription. With many concurrent subscriptions, the cumulative in-memory row allocations create heap pressure that triggers GC pauses affecting all users of the mirror node.

### Finding Description

**Exact code path:** `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, `poll()` method, lines 65–79; `isComplete()` method, lines 121–128.

**Root cause — no limit path in `poll()`:**

When a client submits a filter with `limit=0`, `filter.hasLimit()` returns `false` (line 39–41 of `TopicMessageFilter.java`):

```java
// TopicMessageFilter.java line 39-41
public boolean hasLimit() {
    return limit > 0;
}
```

In `poll()`, this causes `limit` to be set to `Integer.MAX_VALUE`, and `pageSize` is then capped only by `maxPageSize`:

```java
// PollingTopicMessageRetriever.java lines 68-71
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getTotal().get())
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, context.getMaxPageSize());
``` [1](#0-0) 

Each poll then materializes up to `maxPageSize` rows (5000 unthrottled, 1000 throttled) via:

```java
// line 78
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
``` [2](#0-1) 

**Root cause — infinite polling for throttled subscriptions with no limit:**

`isComplete()` for the throttled path returns `false` (keeps polling) as long as the last page was full:

```java
// lines 124-125
if (throttled) {
    return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
}
``` [3](#0-2) 

For a topic with millions of messages and no limit, the throttled retriever polls indefinitely (until `retrieverProperties.getTimeout()` fires), loading 1000 rows per poll per subscription.

**Why existing checks fail:**
- `maxPageSize` caps rows *per poll*, not *per concurrent subscription*.
- `timeout` bounds individual subscription lifetime but does not limit how many concurrent subscriptions exist simultaneously.
- No connection-level or IP-level subscription count limit is visible in `GrpcProperties` or `NettyProperties`. [4](#0-3) 

### Impact Explanation
Each concurrent subscription allocates up to `maxPageSize` `TopicMessage` objects per poll cycle. With N concurrent subscriptions, the JVM heap must hold N × maxPageSize objects simultaneously. At 5000 rows × ~1 KB per `TopicMessage` × 100 concurrent subscriptions = ~500 MB of live objects per poll cycle. This causes frequent full GC pauses, degrading latency for all legitimate users. The impact is availability degradation (griefing), not data exfiltration.

### Likelihood Explanation
No authentication is required to open a gRPC `subscribeTopic` stream. Any external client with network access to the gRPC port can open hundreds of streams in a tight loop using any standard gRPC client library. The attack is trivially scriptable, repeatable, and requires no special knowledge beyond the public protobuf API. The only natural throttle is the server-side `timeout`, but new streams can be opened faster than old ones expire.

### Recommendation
1. **Enforce a per-IP or global concurrent subscription cap** in the gRPC server configuration (e.g., via `NettyProperties` or a server interceptor).
2. **Enforce a minimum non-zero `limit`** or a server-side maximum on `limit` in `TopicMessageFilter` validation, preventing indefinite no-limit subscriptions.
3. **Use true JDBC streaming** (scroll cursor / `@QueryHints` with `FETCH_SIZE`) in `findByFilter` so rows are not all materialized into heap at once per poll.
4. **Apply backpressure** at the gRPC layer to prevent a single subscriber from consuming unbounded server resources.

### Proof of Concept
```python
import grpc
import threading
from mirror_node_pb2 import ConsensusTopicQuery
from mirror_node_pb2_grpc import ConsensusServiceStub

TARGET = "mirror-node-grpc:5600"
TOPIC_ID = "0.0.1234"   # topic with millions of historical messages
NUM_STREAMS = 200

def open_stream():
    channel = grpc.insecure_channel(TARGET)
    stub = ConsensusServiceStub(channel)
    req = ConsensusTopicQuery(
        topic_id=TOPIC_ID,
        # limit intentionally omitted (defaults to 0 = no limit)
        # consensus_start_time set to genesis to maximize historical rows
    )
    for _ in stub.subscribeTopic(req):
        pass  # drain slowly to keep subscription alive

threads = [threading.Thread(target=open_stream) for _ in range(NUM_STREAMS)]
for t in threads:
    t.start()
# 200 concurrent subscriptions each loading 1000-5000 rows per poll
# → heap pressure → GC pauses → latency spikes for all users
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-71)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L78-78)
```java
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
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
