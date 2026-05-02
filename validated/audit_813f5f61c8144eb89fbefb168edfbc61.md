Based on my thorough review of the actual code, the vulnerability is confirmed. Here is the audit report:

---

Audit Report

## Title
Integer Overflow in `PollingTopicListener.poll()` Bypasses `maxPageSize` Cap, Enabling Unbounded DB Queries

## Summary
In `PollingTopicListener.poll()`, the expression `(int)(filter.getLimit() - context.getCount().get())` silently narrows a `long` to `int`. When a client supplies a `limit` value of `Long.MAX_VALUE` (a valid `uint64` value accepted by the gRPC proto field), the cast produces `-1`. `Math.min(-1, maxPageSize)` returns `-1`, which is stored as `-1L` in the rebuilt filter. Because `hasLimit()` checks `limit > 0`, the value `-1` is treated as "no limit," causing `findByFilter()` to execute an unbounded DB query on every poll interval indefinitely.

## Finding Description

**Step 1 — No upper-bound cap at the gRPC entry point.**

`ConsensusController.toFilter()` maps the gRPC `uint64 limit` field directly to `TopicMessageFilter.limit` with no cap: [1](#0-0) 

**Step 2 — `@Min(0)` on `TopicMessageFilter.limit` only rejects negative input; `Long.MAX_VALUE` passes.** [2](#0-1) 

**Step 3 — `TopicMessageServiceImpl.incomingMessages()` forwards the limit as a `long` to `topicListener.listen()`.**

With `filter.getLimit() = Long.MAX_VALUE` and `topicContext.getCount().get() = 0`, `limit = Long.MAX_VALUE` is passed into the new filter: [3](#0-2) 

**Step 4 — The unsafe narrowing cast in `PollingTopicListener.poll()`.** [4](#0-3) 

Arithmetic:
- `(int)(Long.MAX_VALUE - 0)` = `(int)(0x7FFFFFFFFFFFFFFF)` → lower 32 bits = `0xFFFFFFFF` = **`-1`** (signed int)
- `Math.min(-1, 5000)` = **`-1`**
- `filter.toBuilder().limit(-1).build()` → `limit = -1L`

The builder call is **not** a Spring-managed method boundary, so `@Validated`/`@Min(0)` on `TopicMessageFilter` does not fire here.

**Step 5 — `hasLimit()` treats `-1` as "no limit".** [5](#0-4) 

`-1 > 0` is `false`, so `hasLimit()` returns `false`.

**Step 6 — `findByFilter()` never calls `setMaxResults()`, issuing an unbounded query.** [6](#0-5) 

**Note:** The identical overflow pattern also exists in `PollingTopicMessageRetriever.poll()` (used for historical retrieval): [7](#0-6) 

**Why existing checks fail:**
- `@Min(0)` on `TopicMessageFilter.limit` only rejects negative input at Spring-validated method boundaries; `Long.MAX_VALUE` passes.
- `@Validated` / `@Valid` on `subscribeTopic` validates the original filter, not the internally rebuilt filter in `poll()`.
- `Math.min(limit, maxPageSize)` is defeated when `limit` is already negative after the overflow.
- `hasLimit()` (`limit > 0`) inadvertently treats the overflowed negative value as "unlimited."
- The outer `flux.take(filter.getLimit())` in `subscribeTopic()` uses the original `Long.MAX_VALUE`, which is effectively unlimited. [8](#0-7) 

## Impact Explanation
Every poll cycle (default every 500 ms, configurable via `hiero.mirror.grpc.listener.interval`) issues a full table scan against `topic_message` for the subscribed topic with no `LIMIT` clause. On a busy topic with millions of messages, this saturates DB I/O, memory, and connection pool resources. Multiple concurrent subscriptions with this payload amplify the effect linearly. The `maxPageSize` protection — the only intended safeguard against large result sets in the polling path — is completely bypassed. [9](#0-8) 

## Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication required. The attacker only needs to send a `ConsensusTopicQuery` with `limit` set to any value greater than `2147483647` (e.g., `9223372036854775807`). No special privileges, tokens, or prior knowledge beyond a valid topic ID are required. The attack is trivially repeatable and scriptable with any gRPC client. This affects deployments configured with `hiero.mirror.grpc.listener.type=POLL`. [10](#0-9) 

## Recommendation

**Primary fix** — Eliminate the narrowing cast in both `PollingTopicListener.poll()` and `PollingTopicMessageRetriever.poll()` by computing the page size entirely in `long` arithmetic before clamping to `int`:

```java
// In PollingTopicListener.poll() and PollingTopicMessageRetriever.poll()
long remaining = filter.hasLimit()
    ? filter.getLimit() - context.getCount().get()
    : (long) listenerProperties.getMaxPageSize();
int pageSize = (int) Math.min(Math.max(remaining, 0L), listenerProperties.getMaxPageSize());
```

This ensures `pageSize` is always in `[0, maxPageSize]` regardless of the input `limit`.

**Secondary fix** — Add an upper-bound cap on `TopicMessageFilter.limit` at the gRPC entry point in `ConsensusController.toFilter()`, or add a `@Max` constraint on the `limit` field in `TopicMessageFilter`.

**Tertiary fix** — Validate the rebuilt filter before passing it to `findByFilter()`, or add a guard in `findByFilter()` that treats any non-positive limit as `hasLimit() == false` only when the value is exactly `0`, and rejects negative values.

## Proof of Concept

Using `grpcurl` against a mirror node configured with `POLL` listener type:

```bash
grpcurl -plaintext \
  -d '{
    "topicID": {"topicNum": 1234},
    "limit": 9223372036854775807
  }' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Expected behavior:** The server accepts the request (passes `@Min(0)` validation). Inside `PollingTopicListener.poll()`, `(int)(9223372036854775807L - 0)` = `-1`. `Math.min(-1, 5000)` = `-1`. The rebuilt filter has `limit = -1L`, `hasLimit()` returns `false`, and `findByFilter()` issues an unbounded `SELECT` with no `LIMIT` clause every 500 ms for the lifetime of the subscription. [11](#0-10) [12](#0-11)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-61)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L26-30)
```java
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L37-43)
```java
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```
