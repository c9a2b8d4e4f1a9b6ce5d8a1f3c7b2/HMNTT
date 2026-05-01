### Title
Integer Narrowing Cast Overflow in `PollingTopicListener.poll()` Causes Unbounded Database Query

### Summary
In `PollingTopicListener.poll()`, the expression `(int)(filter.getLimit() - context.getCount().get())` performs an unsafe narrowing cast from `long` to `int`. When a user supplies `limit = Long.MAX_VALUE` (a valid `uint64` value accepted by the protobuf API and passing `@Min(0)` validation), the cast produces `-1`. This negative `pageSize` is then passed to `findByFilter()`, where `hasLimit()` returns `false` for negative values, causing `setMaxResults()` to never be called — resulting in an unbounded SQL query on every poll cycle.

### Finding Description

**Exact code path:**

`PollingTopicListener.java`, lines 54–59:
```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())  // line 55: unsafe cast
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());  // line 57
...
var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();  // line 59
```

**Step-by-step overflow:**

1. User sends `limit = Long.MAX_VALUE` (`9223372036854775807L`).
2. `filter.hasLimit()` → `Long.MAX_VALUE > 0` → `true`, so the cast branch is taken.
3. `filter.getLimit() - context.getCount().get()` = `Long.MAX_VALUE - 0L` = `Long.MAX_VALUE`.
4. `(int) Long.MAX_VALUE` = `-1` (Java truncates to lower 32 bits: `0xFFFFFFFF` = `-1` signed).
5. `Math.min(-1, 5000)` = `-1` → `pageSize = -1`.
6. `filter.toBuilder().limit(-1).build()` — Lombok builder does **not** trigger Bean Validation, so `@Min(0)` on `TopicMessageFilter.limit` is not enforced here.

**In `TopicMessageRepositoryCustomImpl.findByFilter()`, lines 51–53:**
```java
if (filter.hasLimit()) {          // hasLimit() = (-1 > 0) = false → skipped
    typedQuery.setMaxResults(...);
}
```
`setMaxResults()` is never called. The JPA query runs with **no row limit**, returning every matching `TopicMessage` row from `startTime` onward.

**Why existing checks fail:**

- `@Min(0)` on `TopicMessageFilter.limit` is a Bean Validation constraint enforced only at Spring injection boundaries. The internal `toBuilder().limit(-1).build()` call bypasses it entirely.
- `hasLimit()` (`limit > 0`) correctly guards `setMaxResults()` in the repository, but the negative value produced by the overflow is indistinguishable from "no limit set," so the guard silently disables the limit instead of rejecting it.
- Any `limit > Integer.MAX_VALUE` (not just `Long.MAX_VALUE`) triggers the same overflow. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

Every poll interval (default 500 ms), the listener fires an unbounded `SELECT * FROM topic_message WHERE topic_id = ? AND consensus_timestamp >= ?` with no `LIMIT` clause. For a busy topic with millions of messages, this:

- Exhausts JVM heap (all results loaded via `getResultList().stream()`).
- Saturates the database connection pool and I/O.
- Blocks other subscribers' queries, causing a full service-level DoS for the gRPC mirror node.

The impact is amplified because the poll loop repeats indefinitely (`RepeatSpec.times(Long.MAX_VALUE)`), so the unbounded query fires continuously until the subscription is cancelled or the process crashes. [4](#0-3) [5](#0-4) 

### Likelihood Explanation

- **No authentication required.** The gRPC `subscribeTopic` endpoint is publicly accessible.
- **Trivially triggered.** A single gRPC `ConsensusTopicQuery` with `limit = 9223372036854775807` (max `uint64`) is sufficient.
- **Passes all input validation.** `@Min(0)` accepts `Long.MAX_VALUE`; no upper-bound cap exists on the `limit` field.
- **Repeatable and persistent.** One open subscription continuously hammers the database until the connection is dropped. [6](#0-5) 

### Recommendation

Replace the unsafe narrowing cast with an explicit clamp before casting:

```java
// In PollingTopicListener.poll(), line 54-56:
long remaining = filter.getLimit() - context.getCount().get();
int limit = filter.hasLimit()
        ? (int) Math.min(remaining, Integer.MAX_VALUE)  // clamp before cast
        : Integer.MAX_VALUE;
```

Additionally, add an upper-bound validation on `TopicMessageFilter.limit` at the gRPC service entry point (e.g., `@Max(Long.MAX_VALUE / 2)` or a domain-specific cap), and consider adding a guard in `findByFilter` that rejects or clamps negative limit values defensively. [7](#0-6) 

### Proof of Concept

**Preconditions:** Mirror node running with `listenerProperties.type = POLL`, a known topic ID with existing messages.

**Steps:**

1. Connect to the gRPC mirror node endpoint.
2. Send a `subscribeTopic` request:
   ```
   ConsensusTopicQuery {
     topicID: { shardNum: 0, realmNum: 0, topicNum: <valid_topic_id> }
     consensusStartTime: { seconds: 0, nanos: 0 }
     limit: 9223372036854775807   // Long.MAX_VALUE
   }
   ```
3. The subscription is accepted (passes `@Min(0)` validation).
4. On the first poll (500 ms later), `poll()` computes `(int)(9223372036854775807L - 0L)` = `-1`.
5. `pageSize = Math.min(-1, 5000)` = `-1`.
6. `findByFilter` is called with `limit = -1`; `hasLimit()` returns `false`; no `setMaxResults()` is set.
7. The database executes `SELECT * FROM topic_message WHERE topic_id = ? AND consensus_timestamp >= ?` with no `LIMIT`.
8. This repeats every 500 ms indefinitely, exhausting database and JVM resources. [8](#0-7) [9](#0-8)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-61)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L33-61)
```java
    public Stream<TopicMessage> findByFilter(TopicMessageFilter filter) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<TopicMessage> query = cb.createQuery(TopicMessage.class);
        Root<TopicMessage> root = query.from(TopicMessage.class);

        Predicate predicate = cb.and(
                cb.equal(root.get(TOPIC_ID), filter.getTopicId()),
                cb.greaterThanOrEqualTo(root.get(CONSENSUS_TIMESTAMP), filter.getStartTime()));

        if (filter.getEndTime() != null) {
            predicate = cb.and(predicate, cb.lessThan(root.get(CONSENSUS_TIMESTAMP), filter.getEndTime()));
        }

        query = query.select(root).where(predicate).orderBy(cb.asc(root.get(CONSENSUS_TIMESTAMP)));

        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
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
