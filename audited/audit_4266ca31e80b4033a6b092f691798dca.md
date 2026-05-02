### Title
Integer Overflow in `poll()` Bypasses Page-Size Cap, Enabling Unbounded DB Query DoS

### Summary
In `PollingTopicMessageRetriever.poll()`, the expression `(int)(filter.getLimit() - context.getTotal().get())` performs an unchecked narrowing cast from `long` to `int`. When an attacker supplies a `limit` value of `Long.MAX_VALUE` (a valid `uint64` in the gRPC proto), the cast overflows to `-1`, which then causes `Math.min(-1, maxPageSize)` to produce `-1` as the page size. The resulting internal filter has `limit = -1`, which causes `hasLimit()` to return `false` in the repository layer, skipping `setMaxResults()` entirely and issuing an unbounded database query.

### Finding Description

**Exact code path:**

`ConsensusController.toFilter()` at line 56 accepts the raw proto `uint64` limit with no upper-bound check: [1](#0-0) 

The filter is built with `limit = Long.MAX_VALUE`. The only constraint on `TopicMessageFilter.limit` is `@Min(0)`: [2](#0-1) 

`Long.MAX_VALUE >= 0`, so Spring validation passes. Inside `poll()`, the narrowing cast overflows: [3](#0-2) 

- `(int)(Long.MAX_VALUE - 0)` = `(int)(0x7FFFFFFFFFFFFFFF)` = `(int)(0xFFFFFFFF)` = **`-1`**
- `Math.min(-1, maxPageSize)` = **`-1`**

The internal filter is rebuilt via `toBuilder().limit(-1).build()` — a direct Lombok builder call that does **not** go through Spring's validation AOP proxy, so `@Min(0)` is never enforced here: [4](#0-3) 

In `TopicMessageRepositoryCustomImpl.findByFilter()`, `hasLimit()` is defined as `limit > 0`: [5](#0-4) 

With `limit = -1`, `hasLimit()` returns `false`, so `setMaxResults()` is never called: [6](#0-5) 

The JPA query then fetches **every row** in `topic_message` matching the topic and start-time predicate, with no row limit.

### Impact Explanation

An unbounded `SELECT *` against the `topic_message` table can return millions of rows, consuming all available DB memory, saturating the DB connection pool, and blocking legitimate queries. Because `getResultList()` materialises the entire result set into a Java `List` before streaming, the JVM heap is also exhausted. A single malicious subscription is sufficient to render the mirror node's gRPC service unavailable for all other users — a non-network DoS with no rate-limiting or authentication requirement.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication. The `limit` field in `ConsensusTopicQuery` is `uint64`; any gRPC client library can trivially set it to `Long.MAX_VALUE` (e.g., `setLimit(Long.MAX_VALUE)` in Java or `limit: 9223372036854775807` in any other language). The attack is deterministic, requires a single RPC call, and is trivially repeatable. No special knowledge of the system internals is needed.

### Recommendation

1. **Add an upper-bound cap before the cast.** In `poll()`, clamp the remaining limit to `Integer.MAX_VALUE` before casting:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = filter.hasLimit()
       ? (int) Math.min(remaining, Integer.MAX_VALUE)
       : Integer.MAX_VALUE;
   ```
2. **Add a `@Max` constraint** on `TopicMessageFilter.limit` (e.g., `@Max(Integer.MAX_VALUE)`) so the initial filter is rejected at the Spring validation boundary before it ever reaches the retriever.
3. Apply the same fix to the identical pattern in `PollingTopicListener.poll()` at line 54–55.

### Proof of Concept

```java
// gRPC client (Java)
ManagedChannel channel = ManagedChannelBuilder.forAddress("mirror-node-host", 5600)
    .usePlaintext().build();
ConsensusServiceGrpc.ConsensusServiceBlockingStub stub =
    ConsensusServiceGrpc.newBlockingStub(channel);

ConsensusTopicQuery query = ConsensusTopicQuery.newBuilder()
    .setTopicID(TopicID.newBuilder().setTopicNum(1).build())
    .setConsensusStartTime(Timestamp.newBuilder().setSeconds(0).build())
    .setLimit(Long.MAX_VALUE)   // uint64 = 9223372036854775807, passes @Min(0)
    .build();

// Triggers: (int)(Long.MAX_VALUE - 0) = -1
// → pageSize = Math.min(-1, maxPageSize) = -1
// → newFilter.limit = -1 → hasLimit() = false → no setMaxResults()
// → unbounded SELECT against topic_message table
stub.subscribeTopic(query).forEachRemaining(r -> {}); // blocks DB until OOM/timeout
```

**Expected result:** The DB executes `SELECT * FROM topic_message WHERE topic_id = ? AND consensus_timestamp >= ?` with no `LIMIT` clause, returning all rows and causing memory exhaustion / service unavailability.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-56)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L75-78)
```java
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-53)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```
