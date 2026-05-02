### Title
Integer Overflow in `poll()` Removes SQL LIMIT, Enabling Unlimited Full-Index Scan via Crafted `limit` Value

### Summary
In `PollingTopicMessageRetriever.poll()`, the expression `(int)(filter.getLimit() - context.getTotal().get())` performs an unsafe narrowing cast from `long` to `int`. Any `limit` value greater than `Integer.MAX_VALUE` (e.g., `Integer.MAX_VALUE + 1 = 2147483648L`) overflows to a negative `int`. `Math.min` then selects that negative value as `pageSize`, which is stored as a negative `long` in the rebuilt filter. Since `hasLimit()` returns `false` for negative values, `setMaxResults()` is never called, and the JPA query fetches every row for the topic without any row cap.

### Finding Description

**Exact code path:**

`ConsensusController.toFilter()` reads `query.getLimit()` directly from the protobuf `uint64` field and passes it to `TopicMessageFilter.builder().limit(...)`: [1](#0-0) 

The proto field is declared `uint64`, so any value from `0` to `Long.MAX_VALUE` is a valid positive Java `long`: [2](#0-1) 

`TopicMessageFilter` only enforces `@Min(0)` on `limit` — there is no `@Max` constraint: [3](#0-2) 

In `poll()`, the narrowing cast overflows for any `limit > Integer.MAX_VALUE`: [4](#0-3) 

`Math.min(negative_int, positive_maxPageSize)` returns the negative value, which is widened back to a negative `long` and stored in `newFilter`: [5](#0-4) 

`hasLimit()` returns `false` for any value `<= 0`, so `setMaxResults()` is never called: [6](#0-5) [7](#0-6) 

The JPA query therefore executes with no `LIMIT` clause and loads the entire result set into memory via `getResultList()`: [8](#0-7) 

**Why existing checks fail:**

- `@Min(0)` on `TopicMessageFilter.limit` only rejects negative inputs; `Integer.MAX_VALUE + 1` through `Long.MAX_VALUE` all pass.
- Spring `@Validated` on `TopicMessageServiceImpl` validates the *original* filter supplied by the caller, but the poisoned `newFilter` is constructed internally inside `poll()` and passed directly to the repository, bypassing all Spring AOP validation.
- `isComplete()` uses `filter.getLimit() == total.get()` — since `filter.getLimit()` is `Long.MAX_VALUE`, this equality is never reached, so the polling loop does not self-terminate early. [9](#0-8) 

### Impact Explanation
On each poll cycle the repository executes a query with no row limit against the `topic_message` table, filtered only by `topic_id` and `consensus_timestamp >= startTime`. For a high-volume topic this can return millions of rows, all loaded into a Java `List` in one call. This causes:
- **Memory exhaustion / OOM** on the mirror-node JVM.
- **Heavy database I/O** proportional to the number of stored messages for the targeted topic.
- **Denial of service** for all other subscribers sharing the same node, repeatable on every poll interval for as long as the subscription is open.

Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation
The gRPC endpoint is publicly reachable with no authentication. The protobuf `uint64 limit` field accepts any 64-bit value. An attacker needs only to send a single `subscribeTopic` RPC with `limit = 2147483648` (one above `Integer.MAX_VALUE`). The attack is trivially scriptable, repeatable, and requires no prior knowledge of the system beyond the public proto definition. [10](#0-9) 

### Recommendation
1. **Add an upper-bound constraint** on `TopicMessageFilter.limit`, e.g. `@Max(Long.MAX_VALUE)` is insufficient — cap it at a safe operational maximum such as `@Max(Integer.MAX_VALUE)` or a configurable property value.
2. **Replace the unsafe cast** in `poll()` with an explicit clamp:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = (remaining > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int) remaining;
   ```
3. **Validate `newFilter`** before passing it to the repository, or assert `pageSize > 0` and short-circuit if it is not. [11](#0-10) 

### Proof of Concept
```python
# grpc client pseudocode (e.g. using grpcio + generated stubs)
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto.services import basic_types_pb2

channel = grpc.insecure_channel("mirror-node-host:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1),
    limit=2147483648,          # Integer.MAX_VALUE + 1 → overflows to -2147483648 after cast
)

# Each poll now issues: SELECT ... FROM topic_message WHERE topic_id=1 AND ...
# with NO LIMIT clause, loading all rows into memory.
for response in stub.subscribeTopic(query):
    pass   # server OOMs or becomes unresponsive
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-56)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L14-26)
```text
message ConsensusTopicQuery {
    .proto.TopicID topicID = 1; // A required topic ID to retrieve messages for.

    // Include messages which reached consensus on or after this time. Defaults to current time if not set.
    .proto.Timestamp consensusStartTime = 2;

    // Include messages which reached consensus before this time. If not set it will receive indefinitely.
    .proto.Timestamp consensusEndTime = 3;

    // The maximum number of messages to receive before stopping. If not set or set to zero it will return messages
    // indefinitely.
    uint64 limit = 4;
}
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-53)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-61)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
    }
```
