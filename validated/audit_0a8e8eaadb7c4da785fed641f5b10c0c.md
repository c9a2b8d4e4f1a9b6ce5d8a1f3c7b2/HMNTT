I need to verify each step of the claim against the actual code before rendering a verdict.

All code references have been verified against the actual source. Every step of the chain is confirmed.

---

Audit Report

## Title
Integer Overflow in `PollingTopicListener.poll()` Bypasses Limit Guard, Causing Unbounded Repeated Database Queries

## Summary
A gRPC subscriber supplying `limit = Long.MAX_VALUE` in a `ConsensusTopicQuery` triggers a silent narrowing-cast overflow inside `PollingTopicListener.poll()`. The resulting `-1` value causes `TopicMessageFilter.hasLimit()` to return `false`, so `findByFilter()` issues a full, row-unlimited JPA query on every poll interval for the lifetime of the subscription.

## Finding Description

**1. No upper-bound cap at the entry point.**

`ConsensusController.toFilter()` maps the protobuf `uint64 limit` field directly to `TopicMessageFilter.limit` with no maximum:

```java
final var filter = TopicMessageFilter.builder().limit(query.getLimit());
``` [1](#0-0) 

The only constraint on `TopicMessageFilter.limit` is `@Min(0)`, which `Long.MAX_VALUE` trivially satisfies: [2](#0-1) 

**2. Propagation to the listener.**

`TopicMessageServiceImpl.incomingMessages()` computes `limit = Long.MAX_VALUE - 0 = Long.MAX_VALUE` (no overflow at `long` width) and passes it to `topicListener.listen(newFilter)`: [3](#0-2) 

**3. The narrowing-cast overflow in `poll()`.**

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())  // (int)(Long.MAX_VALUE - 0) = -1
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize()); // Math.min(-1, 5000) = -1
``` [4](#0-3) 

`(int) 0x7FFFFFFFFFFFFFFF = 0xFFFFFFFF = -1`. `Math.min(-1, any_positive) = -1`. The rebuilt filter carries `limit = -1`.

**4. `hasLimit()` returns `false` for `-1`.**

```java
public boolean hasLimit() {
    return limit > 0;   // -1 > 0 → false
}
``` [5](#0-4) 

**5. `findByFilter()` silently omits `setMaxResults`.**

```java
if (filter.hasLimit()) {                              // false → branch skipped
    typedQuery.setMaxResults((int) filter.getLimit());
}
``` [6](#0-5) 

No `LIMIT` clause is added to the SQL query; every matching row for the topic is returned.

**6. The polling loop repeats indefinitely.**

`PollingTopicListener.listen()` schedules `RepeatSpec.times(Long.MAX_VALUE)`, and the outer `flux.take(Long.MAX_VALUE)` in `subscribeTopic` requires `Long.MAX_VALUE` messages to terminate — effectively never: [7](#0-6) [8](#0-7) 

## Impact Explanation
Every poll cycle (default 500 ms, configurable via `listenerProperties.getInterval()`) issues a full table scan against `topic_message` for the subscribed topic with no row limit. On a busy topic with millions of messages, each query consumes significant database CPU, memory, and I/O. Multiple concurrent attackers amplify this linearly. The polling loop runs for the entire subscription lifetime (effectively forever), making this a sustained resource-exhaustion attack against the database tier.

## Likelihood Explanation
The attack requires only a valid gRPC client and knowledge of any existing topic ID. No authentication, tokens, or privileged access are needed. The protobuf `uint64` field natively accepts `Long.MAX_VALUE`. The exploit is reproducible with a single `grpcurl` invocation and is repeatable by any number of concurrent clients.

## Recommendation
Apply a server-side cap on the `limit` field before it reaches `TopicMessageFilter`. In `ConsensusController.toFilter()`, clamp the value:

```java
filter.limit(Math.min(query.getLimit(), MAX_ALLOWED_LIMIT));
```

Additionally, guard the narrowing cast in `PollingTopicListener.poll()` and `PollingTopicMessageRetriever.poll()` against negative results:

```java
int limit = filter.hasLimit()
        ? (int) Math.max(0, Math.min(filter.getLimit() - context.getCount().get(), Integer.MAX_VALUE))
        : Integer.MAX_VALUE;
```

A `@Max` constraint on `TopicMessageFilter.limit` would also prevent excessively large values from entering the system.

## Proof of Concept

```bash
grpcurl -plaintext \
  -d '{
    "topicID": {"topicNum": 1234},
    "consensusStartTime": {"seconds": 0},
    "limit": 9223372036854775807
  }' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Trace through the code:**
1. `query.getLimit()` = `Long.MAX_VALUE` → stored in `TopicMessageFilter.limit` (passes `@Min(0)`).
2. `incomingMessages()` computes `limit = Long.MAX_VALUE - 0 = Long.MAX_VALUE`; passes to `PollingTopicListener`.
3. `poll()`: `(int)(Long.MAX_VALUE - 0)` = `-1`; `Math.min(-1, 5000)` = `-1`; `newFilter.limit = -1`.
4. `hasLimit()` returns `false`; `setMaxResults` is never called.
5. JPA executes `SELECT * FROM topic_message WHERE topic_id = 1234 AND consensus_timestamp >= 0 ORDER BY consensus_timestamp` — no `LIMIT` clause.
6. Step 3–5 repeats every 500 ms indefinitely via `RepeatSpec.times(Long.MAX_VALUE)`.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L115-118)
```java
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-53)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```
