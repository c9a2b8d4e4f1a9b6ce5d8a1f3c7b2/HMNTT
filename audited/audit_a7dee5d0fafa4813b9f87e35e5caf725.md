### Title
Integer Overflow in `poll()` Causes Unbounded Database Query via Large `limit` Value

### Summary
In `PollingTopicMessageRetriever.poll()`, the expression `(int)(filter.getLimit() - context.getTotal().get())` performs a narrowing cast from `long` to `int` without bounds checking. Any unauthenticated gRPC client can send a `ConsensusTopicQuery` with `limit` set to any value greater than `Integer.MAX_VALUE` (e.g., `2147483648`), which passes the `@Min(0)` validation but causes the `(int)` cast to produce a negative `pageSize`. This negative value is then used to build an internal filter where `hasLimit()` returns `false`, causing the repository to execute an unbounded SQL query with no `LIMIT` clause, returning all matching rows.

### Finding Description

**Entry point** — `ConsensusController.toFilter()` maps the protobuf `uint64 limit` field directly to `TopicMessageFilter.limit` with no upper-bound cap: [1](#0-0) 

The protobuf field is `uint64`, so any value from `1` to `Long.MAX_VALUE` is a valid positive long and passes the only constraint on `TopicMessageFilter.limit`: [2](#0-1) 

There is no `@Max` constraint. The `@Validated`/`@Valid` chain enforced at the service layer only rejects negative values.

**Overflow site** — `PollingTopicMessageRetriever.poll()`, lines 68–71: [3](#0-2) 

With `filter.getLimit() = 2147483648L` (Integer.MAX_VALUE + 1) and `context.getTotal().get() = 0`:
- `long` subtraction: `2147483648L - 0L = 2147483648L` (`0x80000000`)
- `(int)` cast: `0x80000000` → `Integer.MIN_VALUE` = `-2147483648`
- `Math.min(-2147483648, maxPageSize)` = `-2147483648`

**Downstream effect** — the negative `pageSize` is written into a new internal filter via `toBuilder().limit(pageSize)`. In `TopicMessageRepositoryCustomImpl.findByFilter()`: [4](#0-3) 

`hasLimit()` checks `limit > 0`: [5](#0-4) 

Since `limit = -2147483648`, `hasLimit()` returns `false`, `setMaxResults` is never called, and the JPA query returns every row matching the topic/timestamp predicate — a full table scan with no row cap.

### Impact Explanation

Each poll cycle (repeated on a configurable interval, indefinitely for throttled subscribers) issues an unbounded `SELECT *` against the `topic_message` table. On a busy topic with millions of messages, this loads the entire result set into the JVM heap. Multiple concurrent malicious subscriptions amplify the effect, leading to heap exhaustion (OOM), GC pressure, and mirror node service unavailability. The mirror node's gRPC service becomes unresponsive, denying legitimate subscribers access to topic data. The "block processing" framing in the question does not apply — this is a read-only mirror node, not a consensus node — but the DoS impact on the mirror node service is concrete and severe.

### Likelihood Explanation

The exploit requires zero privileges. The gRPC `subscribeTopic` endpoint is publicly accessible. The trigger value (`limit > Integer.MAX_VALUE`) is trivially crafted with any gRPC client (e.g., `grpcurl -d '{"topicID":{"topicNum":1},"limit":2147483648}'`). The condition is deterministic and 100% reproducible. No race condition or timing dependency is required.

### Recommendation

1. **Add an `@Max` constraint** on `TopicMessageFilter.limit` to cap it at a safe value (e.g., `Long.MAX_VALUE` is unnecessary; a practical cap like `Integer.MAX_VALUE` or a configurable property value is sufficient).
2. **Replace the unsafe `(int)` cast** with a safe narrowing: use `Math.min(filter.getLimit() - context.getTotal().get(), (long) context.getMaxPageSize())` keeping the result as `long`, then pass it as `long` to `limit()` on the builder — avoiding the cast entirely.
3. **Cap the limit at the controller layer** in `ConsensusController.toFilter()` before building the filter, e.g., `Math.min(query.getLimit(), someConfiguredMax)`.

### Proof of Concept

```bash
# Send a subscribeTopic request with limit = 2^31 (Integer.MAX_VALUE + 1)
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 1}, "limit": 2147483648}' \
  localhost:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Trace through the code**:
1. `ConsensusController.toFilter()` sets `filter.limit = 2147483648L` — passes `@Min(0)`.
2. `PollingTopicMessageRetriever.poll()`: `(int)(2147483648L - 0L)` = `-2147483648`.
3. `Math.min(-2147483648, maxPageSize)` = `-2147483648` → `pageSize = -2147483648`.
4. `newFilter.limit = -2147483648`; `hasLimit()` → `false`.
5. `typedQuery.setMaxResults(...)` is never called.
6. Full table scan on `topic_message` for the given topic, all rows returned into heap.
7. Repeated every polling interval for the lifetime of the subscription.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-71)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-53)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```
