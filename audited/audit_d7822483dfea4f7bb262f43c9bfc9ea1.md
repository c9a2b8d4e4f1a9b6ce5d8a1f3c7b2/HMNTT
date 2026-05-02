### Title
Integer Overflow in `poll()` Bypasses Database Query Limit, Enabling Unbounded Result Set Fetch

### Summary
In `PollingTopicMessageRetriever.poll()`, the expression `(int) (filter.getLimit() - context.getTotal().get())` silently overflows to a negative integer when `filter.getLimit()` is any value greater than `Integer.MAX_VALUE` (e.g., `Long.MAX_VALUE`). The resulting negative `pageSize` is propagated into a new `TopicMessageFilter` via the internal builder, bypassing Bean Validation. In `TopicMessageRepositoryCustomImpl.findByFilter()`, the `hasLimit()` guard (`limit > 0`) evaluates to `false` for the negative value, so `setMaxResults()` is never called and the JPA query executes without any `LIMIT` clause, fetching all matching rows from the database.

### Finding Description

**Exact code path:**

`ConsensusController.toFilter()` maps the raw proto `uint64` limit field directly to `TopicMessageFilter.limit` with no upper-bound cap: [1](#0-0) 

`TopicMessageFilter` only enforces `@Min(0)` on `limit`, which `Long.MAX_VALUE` satisfies: [2](#0-1) 

In `PollingTopicMessageRetriever.poll()`, the narrowing cast overflows: [3](#0-2) 

- `(int)(Long.MAX_VALUE - 0L)` = `(int) 0x7FFFFFFFFFFFFFFFL` = `0xFFFFFFFF` = **-1**
- `Math.min(-1, maxPageSize)` = **-1**

The negative `pageSize` is written into a new filter via the internal Lombok builder — Bean Validation is **not** re-triggered because `findByFilter()` has no `@Valid` parameter annotation: [4](#0-3) 

In `TopicMessageRepositoryCustomImpl.findByFilter()`, `hasLimit()` checks `limit > 0`. With `limit = -1`, this is `false`, so `setMaxResults()` is **never called**: [5](#0-4) 

The JPA query therefore executes with no `LIMIT` clause and loads the entire matching result set into memory via `getResultList()`: [6](#0-5) 

The identical overflow exists in `PollingTopicListener.poll()`: [7](#0-6) 

**Root cause:** Unsafe narrowing cast from `long` to `int` with no overflow guard, combined with `hasLimit()` using a `> 0` check that silently treats negative values as "no limit."

**Why existing checks fail:**
- `@Min(0)` on `TopicMessageFilter.limit` only rejects negative user-supplied values; `Long.MAX_VALUE` passes.
- `@Validated`/`@Valid` on `TopicMessageService.subscribeTopic()` validates the original filter, not the internally-constructed `newFilter`.
- `Math.min(limit, maxPageSize)` does not protect against a negative `limit` — it returns the negative value unchanged.
- `flux.take(filter.getLimit())` in `TopicMessageServiceImpl` applies `Long.MAX_VALUE` as the take count, which is effectively unlimited. [8](#0-7) 

### Impact Explanation
An attacker causes the server to execute an unbounded `SELECT` against the `topic_message` table for any topic with a large message history. The entire result set is materialized in JVM heap via `getResultList()`. On a busy network with millions of topic messages, this can exhaust server memory, degrade database performance for all users, and cause cascading failures. The `retrieverProperties.getTimeout()` provides a time-based backstop, but the damage (heap pressure, DB load) occurs before the timeout fires. Multiple concurrent requests amplify the impact into a reliable DoS.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication requirement visible in the code. Any client can craft a `ConsensusTopicQuery` protobuf message with `limit` set to `Long.MAX_VALUE` (or any value ≥ `2147483648L` that overflows to a negative int). The exploit requires no special knowledge beyond the public HCS gRPC API specification. It is trivially repeatable and scriptable.

### Recommendation
1. **Fix the cast:** Replace the unsafe narrowing cast with a saturating conversion:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = remaining > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) remaining;
   ```
2. **Add an upper-bound constraint** on `TopicMessageFilter.limit`:
   ```java
   @Max(Integer.MAX_VALUE)
   @Min(0)
   private long limit;
   ```
3. **Harden `findByFilter()`:** Add a defensive guard so that a negative or zero limit always results in `setMaxResults(0)` or an early empty return, rather than an unbounded query.
4. Apply the same fix to `PollingTopicListener.poll()` at the identical cast on line 55.

### Proof of Concept

**Preconditions:** A topic exists on the network with at least one message. The mirror node gRPC endpoint is reachable.

**Steps:**
1. Construct a `ConsensusTopicQuery` protobuf with:
   - `topicID` = any valid topic
   - `consensusStartTime` = epoch (0 seconds)
   - `limit` = `9223372036854775807` (`Long.MAX_VALUE`)
2. Send the request to the mirror node gRPC endpoint (`subscribeTopic`).
3. **Trigger:** `poll()` computes `(int)(Long.MAX_VALUE - 0) = -1`; `pageSize = -1`; `newFilter.limit = -1`.
4. **Result:** `findByFilter()` skips `setMaxResults()` and issues an unbounded SQL query equivalent to:
   ```sql
   SELECT * FROM topic_message
   WHERE topic_id = ? AND consensus_timestamp >= ?
   ORDER BY consensus_timestamp ASC
   ```
   with no `LIMIT` clause, loading all matching rows into heap.
5. Repeat concurrently from multiple clients to amplify memory and DB pressure.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-60)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```
