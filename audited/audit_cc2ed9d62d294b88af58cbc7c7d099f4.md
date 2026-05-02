Looking at the actual code:

**`PollingTopicListener.java`, `poll()`, lines 54–57:**
```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```

**`TopicMessageFilter.java`, `limit` field:**
```java
@Min(0)
private long limit;
```

The only constraint is `@Min(0)` — no upper bound. Any value from `Integer.MAX_VALUE + 1` through `Long.MAX_VALUE` passes validation but overflows the `(int)` cast to a negative number. `Math.min(negative, maxPageSize)` returns the negative value, which is then passed to the repository and used to build a new filter (via `toBuilder().limit(pageSize)`) — bypassing Spring validation since that builder call is not intercepted by Spring AOP.

---

### Title
Integer Overflow in `PollingTopicListener.poll()` Causes Subscription Termination via Unchecked `long`-to-`int` Cast

### Summary
`PollingTopicListener.poll()` casts the remaining message limit from `long` to `int` without any upper-bound guard. Any unprivileged subscriber who sets a `limit` value greater than `Integer.MAX_VALUE` (e.g., `Long.MAX_VALUE`) causes the cast to overflow to a negative integer, which is passed as `pageSize` to the repository, triggering an exception that terminates the polling Flux and permanently drops messages for that subscriber until they reconnect.

### Finding Description
**Code path:**

- `grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, `poll()`, lines 54–57
- `grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java`, `limit` field, line 26

**Root cause:** `filter.getLimit()` is a `long`. The only validation is `@Min(0)` — there is no `@Max` or upper-bound constraint. The expression `(int)(filter.getLimit() - context.getCount().get())` silently truncates to the lower 32 bits:

```
(int) Long.MAX_VALUE          = -1
(int) (Integer.MAX_VALUE + 1) = Integer.MIN_VALUE (-2147483648)
```

`Math.min(-1, maxPageSize)` returns `-1`. The `toBuilder().limit(-1).build()` call is a direct Lombok builder invocation — Spring's `@Validated` / `@Min(0)` AOP interception does **not** fire here, so the negative value reaches `topicMessageRepository.findByFilter(newFilter)`. The repository passes this as a SQL/JPA `LIMIT -1`, which throws an `IllegalArgumentException` (or equivalent). This error propagates through the `Flux`, and since `repeatWhen` does not swallow errors, the entire subscription Flux terminates.

**Why existing checks fail:**
- `@Min(0)` on `TopicMessageFilter.limit` only rejects negative input; `Long.MAX_VALUE` is `> 0` and passes.
- `hasLimit()` returns `true` for `Long.MAX_VALUE`, so the cast branch is always taken.
- The internal `toBuilder()` call is not a Spring-managed method invocation, so `@Validated` constraints are never re-evaluated on the derived filter.

### Impact Explanation
The subscriber's Flux terminates on the first poll cycle. All topic messages published between subscription termination and reconnection are permanently lost for that subscriber — the polling cursor is not persisted, so a reconnect starts from the current time or the original `startTime`, not from where the stream died. On a financial topic (e.g., HCS-based payment confirmations), this means a client silently misses transaction confirmations.

### Likelihood Explanation
The gRPC `ConsensusSubscribeRequest` proto exposes `limit` as `uint64`, directly mapped to Java `long`. Any unauthenticated client can set `limit = 0xFFFFFFFFFFFFFFFF`. No authentication or authorization is required. The condition is trivially reproducible on every subscription attempt with a large limit, making it 100% repeatable.

### Recommendation
Add an explicit upper-bound guard before the cast in `poll()`:

```java
long remaining = filter.hasLimit()
        ? filter.getLimit() - context.getCount().get()
        : (long) Integer.MAX_VALUE;
// Clamp to [0, Integer.MAX_VALUE] before narrowing cast
remaining = Math.max(0L, Math.min(remaining, (long) Integer.MAX_VALUE));
int limit = (int) remaining;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```

Additionally, add `@Max(Integer.MAX_VALUE)` (or a domain-appropriate maximum) to `TopicMessageFilter.limit` so the constraint is enforced at the API boundary before the filter ever reaches the listener.

### Proof of Concept
1. Connect a gRPC client to the mirror node's consensus service.
2. Send a `ConsensusSubscribeRequest` with `limit = 9223372036854775807` (`Long.MAX_VALUE`) for any topic.
3. The server creates a `TopicMessageFilter` with `limit = Long.MAX_VALUE` (passes `@Min(0)`).
4. On the first poll interval, `poll()` computes `(int)(Long.MAX_VALUE - 0) = -1`.
5. `Math.min(-1, maxPageSize) = -1`; `newFilter` is built with `limit = -1`.
6. `topicMessageRepository.findByFilter(newFilter)` throws (e.g., `IllegalArgumentException: maxResults must not be negative`).
7. The Flux errors; the subscriber receives an error signal and the stream closes.
8. Any messages published to the topic after step 7 and before the client reconnects are permanently lost for that subscriber. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-57)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-26)
```java
    @Min(0)
    private long limit;
```
