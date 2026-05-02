### Title
Integer Narrowing Cast Overflow in `PollingTopicListener.poll()` Bypasses `maxPageSize` Cap, Enabling Unlimited DB Queries

### Summary
In `PollingTopicListener.poll()`, the expression `(int)(filter.getLimit() - context.getCount().get())` performs a narrowing cast from `long` to `int` without overflow protection. When an unprivileged user supplies `limit = Long.MAX_VALUE` (which passes the `@Min(0)` validation), the cast produces `-1`, which is smaller than any positive `maxPageSize`, causing `Math.min(-1, maxPageSize)` to return `-1`. The resulting filter with `limit = -1` causes `hasLimit()` to return `false` in the repository, so `setMaxResults()` is never called and the database returns all matching rows on every poll cycle.

### Finding Description

**Exact code path:**

`PollingTopicListener.java`, lines 54–61:
```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())  // line 55 — overflow here
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());  // line 57 — -1 wins
...
var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();  // line 59 — limit=-1
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));           // line 61
```

**Root cause — narrowing cast without bounds check:**

`filter.getLimit()` is `long`; `context.getCount().get()` is `long` (AtomicLong). The subtraction is a `long` operation, but the result is immediately narrowed to `int` via `(int)(...)`. Java's narrowing primitive conversion discards the upper 32 bits:

```
Long.MAX_VALUE = 0x7FFFFFFFFFFFFFFF
lower 32 bits  = 0xFFFFFFFF  →  (int) = -1
```

So when `filter.getLimit() = Long.MAX_VALUE` and `count = 0`, `limit = -1`.

**Why `Math.min` does not save it:**

`Math.min(-1, 5000)` returns `-1`. The cap is bypassed entirely — the computed `pageSize` is *below* zero, not above `maxPageSize`.

**Why the repository executes an unlimited query:**

`TopicMessageRepositoryCustomImpl.findByFilter()`, lines 51–53:
```java
if (filter.hasLimit()) {
    typedQuery.setMaxResults((int) filter.getLimit());
}
```

`hasLimit()` in `TopicMessageFilter` (line 39–41):
```java
public boolean hasLimit() {
    return limit > 0;
}
```

`-1 > 0` is `false`, so `setMaxResults()` is never called. The JPA query has no row limit and the database returns every matching `topic_message` row from `startTime` onward.

**Why `@Min(0)` does not prevent the initial input:**

`TopicMessageFilter.limit` carries `@Min(0)`, which only rejects values `< 0`. `Long.MAX_VALUE` is `> 0` and passes validation cleanly. The overflow occurs *after* validation, inside `poll()`.

**Why the Lombok builder does not re-validate:**

`filter.toBuilder().limit(-1).build()` constructs a new `TopicMessageFilter` with `limit = -1`. Lombok's builder does not invoke Bean Validation; the `@Min(0)` constraint is never checked on the internally-constructed filter.

**Call chain from user input to unlimited query:**

1. User sends gRPC `subscribeTopic` with `limit = Long.MAX_VALUE`.
2. `TopicMessageServiceImpl.subscribeTopic()` validates the filter — passes.
3. `incomingMessages()` (line 115–118) computes `limit = Long.MAX_VALUE - 0 = Long.MAX_VALUE` and calls `topicListener.listen(newFilter)`.
4. `PollingTopicListener.listen()` schedules repeated calls to `poll()` every 500 ms.
5. `poll()` computes `(int)(Long.MAX_VALUE) = -1`; `pageSize = -1`.
6. `findByFilter()` receives a filter with `limit = -1`; `hasLimit()` is `false`; no `setMaxResults()`; full table scan per poll.

### Impact Explanation

Every 500 ms (the default `interval`), the attacker's subscription triggers a full, unbounded `SELECT` against the `topic_message` table for the chosen topic. On a production node with millions of messages, each query can return gigabytes of data, consuming:

- Database CPU and I/O (full index scan or sequential scan)
- JPA/Hibernate heap (entire result list materialized via `getResultList()`)
- Network bandwidth between DB and mirror node

Multiple concurrent subscriptions from the same or different attackers multiply the effect linearly. Because the subscription persists indefinitely (the `RepeatSpec.times(Long.MAX_VALUE)` loop), a single connection sustains the attack without re-authentication. This constitutes a practical, non-network-based denial-of-service against the database and the mirror node JVM.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication requirement beyond knowing a valid topic ID (which is public on-chain data). The attacker needs only to set the `limit` field in a `ConsensusTopicQuery` protobuf message to `Long.MAX_VALUE` (or any value whose lower 32 bits, after subtracting the current count, produce a positive integer larger than `maxPageSize` — though `Long.MAX_VALUE` is the simplest case that produces `-1` and fully disables the limit). The exploit is trivially reproducible with any gRPC client and requires no elevated privileges, no special knowledge of internals, and no race condition.

### Recommendation

Replace the unsafe narrowing cast with an explicit long-to-int clamp before applying `Math.min`:

```java
// In PollingTopicListener.poll()
long remaining = filter.getLimit() - context.getCount().get();
int limit = filter.hasLimit()
        ? (int) Math.min(remaining, Integer.MAX_VALUE)   // safe clamp
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```

`Math.min(remaining, Integer.MAX_VALUE)` keeps the value in `[0, Integer.MAX_VALUE]` before the narrowing cast, so the result is always a non-negative `int` and `Math.min(limit, maxPageSize)` correctly caps it. The identical pattern exists in `PollingTopicMessageRetriever.poll()` (line 68–69) and should receive the same fix.

Additionally, add a guard in `TopicMessageRepositoryCustomImpl.findByFilter()` as a defence-in-depth measure:

```java
if (filter.hasLimit() && filter.getLimit() > 0) {
    typedQuery.setMaxResults((int) Math.min(filter.getLimit(), Integer.MAX_VALUE));
}
```

### Proof of Concept

**Preconditions:** A running mirror-node gRPC service configured with `ListenerType.POLL`; a known valid `topicId`.

**Steps:**

1. Construct a gRPC `ConsensusTopicQuery` with:
   - `topicID` = any valid topic
   - `consensusStartTime` = epoch (0)
   - `limit` = `9223372036854775807` (`Long.MAX_VALUE`)

2. Open a persistent subscription (e.g., via `grpcurl` or a custom gRPC client).

3. Observe server behaviour:
   - Every 500 ms, `PollingTopicListener.poll()` fires.
   - `(int)(Long.MAX_VALUE - 0) = -1`; `pageSize = -1`.
   - `findByFilter()` executes with no `setMaxResults()`.
   - The full `topic_message` table for that topic is fetched and streamed back.

4. Repeat with N concurrent connections to amplify DB load proportionally.

**Expected result:** Database CPU/IO spikes to 100%; mirror-node heap grows unboundedly; legitimate subscribers experience latency or OOM errors.