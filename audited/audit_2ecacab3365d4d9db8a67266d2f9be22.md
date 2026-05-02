### Title
Integer Overflow in `poll()` Causes Unlimited JPA Query (Full Table Scan DoS) via Crafted gRPC `limit`

### Summary
In `PollingTopicMessageRetriever.poll()`, the expression `(int)(filter.getLimit() - context.getTotal().get())` performs an unchecked narrowing cast from `long` to `int`. When an unprivileged user supplies `limit = 2147483648L` (Integer.MAX_VALUE + 1) via the gRPC `uint64 limit` field, the cast produces `Integer.MIN_VALUE` (-2147483648). This negative value propagates as the `limit` into a new `TopicMessageFilter`, causing `hasLimit()` to return `false` in `TopicMessageRepositoryCustomImpl.findByFilter()`, which skips `setMaxResults()` entirely — resulting in an unbounded full-table scan on every poll iteration, repeated indefinitely.

### Finding Description

**Entry point** — `ConsensusController.toFilter()`: [1](#0-0) 

The proto field `uint64 limit = 4` accepts any 64-bit unsigned value. [2](#0-1) 

The value is passed directly to `TopicMessageFilter.builder().limit(query.getLimit())` with no upper-bound check. The only constraint on `TopicMessageFilter.limit` is `@Min(0)`: [3](#0-2) 

So `limit = 2147483648L` passes `@Valid` validation at the service boundary: [4](#0-3) 

**Overflow site** — `PollingTopicMessageRetriever.poll()`, lines 68–71: [5](#0-4) 

With `filter.getLimit() = 2147483648L` and `context.getTotal().get() = 0`:
- `2147483648L - 0L = 2147483648L`
- `(int)(2147483648L)` = **-2147483648** (Integer.MIN_VALUE — Java narrowing cast discards high bits)
- `Math.min(-2147483648, maxPageSize)` = **-2147483648**

**Propagation** — the poisoned value is written into a new filter: [6](#0-5) 

This internally-built filter is **never re-validated** (no `@Valid` on the builder path).

**Sink** — `TopicMessageRepositoryCustomImpl.findByFilter()`: [7](#0-6) 

`hasLimit()` is `limit > 0`. Since `-2147483648 > 0` is `false`, `setMaxResults()` is **never called**. The JPA query runs with no row limit — a full table scan of `topic_message` for the given topic and start time.

**Loop persistence** — `PollingContext.isComplete()` uses the original filter's `limit = 2147483648L`: [8](#0-7) 

`limitHit` requires `total.get() == 2147483648L`, which is never reached. The polling loop repeats indefinitely, each iteration executing an unbounded query.

### Impact Explanation
Each poll cycle loads the entire `topic_message` table for the targeted topic into JVM heap with no `LIMIT` clause. With a high-volume topic, this exhausts database I/O, connection pool resources, and JVM heap simultaneously. Multiple concurrent connections with this payload amplify the effect. The mirror node's gRPC service becomes unavailable to legitimate subscribers — a targeted, repeatable DoS against the HCS subscription infrastructure. Severity: **High** (availability impact, no authentication required, no funds at direct risk but network observability is disrupted).

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is a public API requiring no credentials. The proto `uint64 limit` field trivially accepts `2147483648`. Any attacker with network access to the mirror node's gRPC port can trigger this with a single protobuf message. The attack is repeatable, requires no special knowledge beyond the proto schema, and can be scripted. Likelihood: **High**.

### Recommendation
1. **Add `@Max(Integer.MAX_VALUE)` to `TopicMessageFilter.limit`** to reject values that cannot safely be narrowed to `int`.
2. **Replace the unsafe narrowing cast** with a safe clamp: replace `(int)(filter.getLimit() - context.getTotal().get())` with `(int) Math.min(filter.getLimit() - context.getTotal().get(), Integer.MAX_VALUE)`.
3. **Guard `findByFilter`**: in `TopicMessageRepositoryCustomImpl`, add an explicit check `if (filter.getLimit() > 0)` (or reuse `hasLimit()`) before calling `setMaxResults`, and add a hard-coded safety cap (e.g., `Math.min((int) filter.getLimit(), MAX_SAFE_PAGE_SIZE)`).
4. **Validate internally-built filters** or use a dedicated internal DTO that enforces `int`-range limits at construction time.

### Proof of Concept

```python
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto import basic_types_pb2

channel = grpc.insecure_channel('mirror-node-host:5600')
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1),  # any existing topic
    limit=2147483648,  # Integer.MAX_VALUE + 1 — triggers overflow
)

# Each response iteration triggers an unbounded full-table scan
for response in stub.subscribeTopic(query):
    pass  # attacker keeps connection open; server polls DB indefinitely
```

**Expected result**: The mirror node executes `SELECT * FROM topic_message WHERE topic_id = ? AND consensus_timestamp >= ?` with **no LIMIT clause** on every poll interval (default: configurable, e.g. 500ms), loading all rows for the topic into memory until the database or JVM is exhausted.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-57)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L24-26)
```text
    // indefinitely.
    uint64 limit = 4;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-26)
```java
    @Min(0)
    private long limit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageService.java (L12-12)
```java
    Flux<TopicMessage> subscribeTopic(@Valid TopicMessageFilter filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-71)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L75-75)
```java
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-53)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```
