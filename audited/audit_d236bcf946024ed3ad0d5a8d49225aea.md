### Title
Integer Overflow in `poll()` Produces Negative `pageSize`, Bypassing `hasLimit()` Guard and Enabling Unbounded Database Queries

### Summary
In `PollingTopicMessageRetriever.poll()`, the remaining-limit calculation casts a `long` subtraction result to `int` without overflow checking. A user-supplied `limit` value greater than `Integer.MAX_VALUE` (valid per `@Min(0)`) causes the cast to wrap to a large negative integer. That negative value is placed into a new `TopicMessageFilter` via `toBuilder().build()` — which never re-runs Bean Validation — so `hasLimit()` returns `false` in the repository, and `setMaxResults` is never called, issuing a fully unbounded SQL query against the database.

### Finding Description

**Exact code path:**

`PollingTopicMessageRetriever.java`, `poll()`, lines 68–75: [1](#0-0) 

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getTotal().get())   // ← long→int cast, no overflow guard
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, context.getMaxPageSize());
...
var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build(); // ← no re-validation
```

**Root cause — two compounding failures:**

1. **Unchecked narrowing cast.** `filter.getLimit()` is a `long`; `context.getTotal().get()` is a `long`. Their difference is computed as a `long` and then silently narrowed to `int`. Any `filter.getLimit()` value in the range `(Integer.MAX_VALUE, Long.MAX_VALUE]` produces a negative `int` on the first poll (when `total == 0`).

2. **Builder bypasses Bean Validation.** `TopicMessageFilter` carries `@Min(0)` on `limit`: [2](#0-1) 

   The `@Validated` annotation on the class only activates Spring method-level validation when the object is passed as a `@Valid` parameter through a Spring proxy. Lombok's `build()` method is plain Java — it never invokes the Jakarta Validation engine. The negative `pageSize` is stored in `newFilter.limit` unchecked.

**Repository consequence:**

`TopicMessageRepositoryCustomImpl.findByFilter()` gates `setMaxResults` on `hasLimit()`: [3](#0-2) 

```java
if (filter.hasLimit()) {          // limit > 0 → false when limit is negative
    typedQuery.setMaxResults(...);
}
```

`hasLimit()` is `limit > 0`: [4](#0-3) 

A negative `limit` makes `hasLimit()` return `false`, so `setMaxResults` is never called and the JPA query returns every row matching the topic/timestamp predicate — no SQL `LIMIT` clause.

**Why existing checks are insufficient:**

- The `@Valid` guard on `TopicMessageService.subscribeTopic()` validates the *original* filter only: [5](#0-4) 

- The `@Validated` + `@Min(0)` annotations on `TopicMessageFilter` are never re-evaluated for the internally-constructed `newFilter`.
- `Math.min(negativeLimit, positiveMaxPageSize)` returns the negative value, not the bounded page size.
- In unthrottled mode, `isComplete()` only returns `true` on `limitHit` (`filter.getLimit() == total.get()`): [6](#0-5) 

  Since `filter.getLimit()` is `2147483648L` and `total` never reaches it, polling repeats for the full `maxPolls` count (default 12), each issuing an unbounded query.

### Impact Explanation

Each unbounded query loads all `topic_message` rows for the targeted topic into JVM heap via `getResultList()`: [7](#0-6) 

For a high-volume topic this can be millions of rows. In unthrottled mode (default `maxPolls = 12`, `pollingFrequency = 20 ms`) the attacker triggers 12 unbounded queries in ~240 ms per subscription. Multiple concurrent subscriptions multiply the effect. Consequences: heap exhaustion / OOM on the gRPC service, database connection pool saturation, and denial of service to all other subscribers. The `retrieverProperties.getTimeout()` (default 60 s) is the only backstop, but the damage accumulates within that window. [8](#0-7) 

### Likelihood Explanation

The gRPC proto field is `uint64 limit`, which Java represents as a signed `long`. Any value above `2,147,483,647` (easily expressible in any gRPC client) triggers the overflow. No authentication or special privilege is required — the `subscribeTopic` RPC is the public API. The attack is trivially repeatable: open a new subscription with `limit = 2147483648` and the overflow fires on the very first `poll()` invocation. The attacker needs no knowledge of internal state.

### Recommendation

1. **Eliminate the narrowing cast.** Replace the `(int)` cast with a bounds-safe computation:
   ```java
   long remaining = filter.hasLimit()
           ? filter.getLimit() - context.getTotal().get()
           : (long) Integer.MAX_VALUE;
   int pageSize = (int) Math.min(remaining, (long) context.getMaxPageSize());
   ```
   This keeps all arithmetic in `long` until the final `Math.min` guarantees the result fits in `int`.

2. **Validate the internally-constructed filter.** Either call `Validator.validate(newFilter)` explicitly before passing it to the repository, or add a defensive guard in `findByFilter`:
   ```java
   if (filter.hasLimit() && filter.getLimit() > 0) {
       typedQuery.setMaxResults((int) filter.getLimit());
   }
   ```

3. **Cap user-supplied `limit` at `Integer.MAX_VALUE`** at the gRPC controller ingestion point before constructing `TopicMessageFilter`, preventing the overflow from ever entering the retrieval pipeline.

### Proof of Concept

**Precondition:** A topic with at least one message exists. The gRPC service is reachable.

**Steps:**

```
# Using grpcurl or any gRPC client:
grpcurl -plaintext \
  -d '{
    "topicID": {"topicNum": <existing_topic_id>},
    "consensusStartTime": {"seconds": 0},
    "limit": 2147483648
  }' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Trigger path:**
1. `limit = 2147483648L` passes `@Min(0)` validation (it is positive).
2. `poll()` computes `(int)(2147483648L - 0L)` = `-2147483648`.
3. `Math.min(-2147483648, 1000)` = `-2147483648`.
4. `newFilter` is built with `limit = -2147483648`; no validation fires.
5. `hasLimit()` returns `false`; `setMaxResults` is not called.
6. `getResultList()` fetches all rows for the topic — unbounded.
7. In unthrottled mode, steps 2–6 repeat 12 times in ~240 ms.

**Expected result:** Server-side heap spike proportional to topic message count; repeated unbounded SQL queries visible in database slow-query logs; potential OOM or severe latency degradation for concurrent subscribers.

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageService.java (L12-12)
```java
    Flux<TopicMessage> subscribeTopic(@Valid TopicMessageFilter filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L36-46)
```java
    public static class UnthrottledProperties {

        @Min(1000)
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
```
