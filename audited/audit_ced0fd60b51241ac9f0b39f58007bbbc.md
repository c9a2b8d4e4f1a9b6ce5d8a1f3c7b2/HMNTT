### Title
Integer Overflow in `poll()` Enables Unlimited Database Query via Crafted `limit` Value

### Summary
In `PollingTopicMessageRetriever.poll()`, the remaining-limit computation `(int)(filter.getLimit() - context.getTotal().get())` performs an unchecked narrowing cast from `long` to `int`. An unprivileged external user can supply `limit = Long.MAX_VALUE - 1` via the gRPC `subscribeTopic` API, causing the cast to produce `-2`, which then causes `Math.min(-2, maxPageSize)` to return `-2`. The resulting internal filter with `limit = -2` bypasses the `hasLimit()` guard in the repository, issuing an unbounded `SELECT` with no `LIMIT` clause against the database.

### Finding Description

**Exact code path:**

`ConsensusController.toFilter()` maps the raw gRPC `uint64 limit` field directly to `TopicMessageFilter.limit` with no upper-bound check: [1](#0-0) 

`TopicMessageFilter` only enforces `@Min(0)` on `limit`, which accepts any non-negative `long`, including `Long.MAX_VALUE - 1`: [2](#0-1) 

Inside `PollingTopicMessageRetriever.poll()`, the remaining limit is computed with an unsafe narrowing cast: [3](#0-2) 

**Root cause — arithmetic:**
- `filter.getLimit()` = `Long.MAX_VALUE - 1` = `0x7FFFFFFFFFFFFFFE`
- `context.getTotal().get()` = `0` (first poll)
- Long subtraction: `0x7FFFFFFFFFFFFFFE - 0` = `0x7FFFFFFFFFFFFFFE`
- `(int)(0x7FFFFFFFFFFFFFFE)` = lower 32 bits = `0xFFFFFFFE` = **-2**
- `Math.min(-2, maxPageSize)` = **-2** (maxPageSize is always ≥ 32)

The corrupted `pageSize = -2` is written into a new internal filter: [4](#0-3) 

In `TopicMessageRepositoryCustomImpl.findByFilter()`, the `setMaxResults` guard uses `hasLimit()` which returns `limit > 0`. Since `-2 > 0` is false, `setMaxResults` is never called and the JPA query is issued **without any LIMIT clause**: [5](#0-4) 

**Why existing checks fail:**

1. `@Min(0)` on `TopicMessageFilter.limit` only rejects negative values. `Long.MAX_VALUE - 1` is positive and passes.
2. The internal `newFilter` built inside `poll()` is constructed via the Lombok builder and passed directly to the repository — it never passes through Spring's AOP validation proxy, so the `@Min(0)` constraint is never re-evaluated on the derived `-2` value.
3. `isComplete()` checks `filter.getLimit() == total.get()`, which requires `total` to reach `Long.MAX_VALUE - 1` — practically impossible — so the retriever loops indefinitely in throttled mode (`numRepeats = Long.MAX_VALUE`): [6](#0-5) 
4. The outer `flux.take(filter.getLimit())` in `TopicMessageServiceImpl` applies `take(Long.MAX_VALUE - 1)`, which is effectively unlimited and does not prevent the unbounded DB queries: [7](#0-6) 
5. The same overflow pattern exists identically in `PollingTopicListener.poll()`: [8](#0-7) 

### Impact Explanation

Each poll cycle issues a `SELECT … WHERE topic_id = ? AND consensus_timestamp >= ?` with no `LIMIT` clause. On a topic with millions of messages, this loads the entire result set into the JPA `getResultList()` call (which materializes all rows into a Java `List` in memory before streaming). Combined with `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` and indefinite repeat in throttled mode, a single malicious subscription causes repeated unbounded queries, leading to heap exhaustion (OOM) and denial of service of the gRPC node. Multiple concurrent such subscriptions amplify the effect. No authentication or special privilege is required — the gRPC `subscribeTopic` endpoint is publicly accessible. [9](#0-8) 

### Likelihood Explanation

The exploit requires only a standard gRPC client and knowledge of a valid topic ID (which is public on-chain data). The attacker sends a single `ConsensusTopicQuery` with `limit = 9223372036854775806` (`Long.MAX_VALUE - 1`). No authentication, no elevated privilege, no race condition, and no special timing is required. The overflow is deterministic and reproducible on every invocation. The attack is repeatable with multiple concurrent connections, each bounded only by `maxConcurrentCallsPerConnection = 5` per connection, but an attacker can open many connections. [10](#0-9) 

### Recommendation

1. **Add an upper-bound validation on `TopicMessageFilter.limit`**: Add `@Max(Integer.MAX_VALUE)` or a domain-appropriate maximum (e.g., `@Max(1_000_000)`) alongside `@Min(0)` on the `limit` field.
2. **Eliminate the unsafe cast**: Replace `(int)(filter.getLimit() - context.getTotal().get())` with a safe computation:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = remaining > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) remaining;
   ```
   Or use `Math.toIntExact` with a catch, or `(int) Math.min(remaining, Integer.MAX_VALUE)`.
3. **Validate the derived `newFilter`**: Before passing the internally constructed filter to the repository, assert `pageSize > 0`.
4. **Apply the same fix to `PollingTopicListener.poll()`** which contains the identical pattern. [2](#0-1) 

### Proof of Concept

```
Preconditions:
- A running hiero-mirror-grpc instance
- A known valid topic ID (e.g., 0.0.1234) with historical messages in the DB

Steps:
1. Using any gRPC client (e.g., grpcurl or a Java client), send:

   ConsensusTopicQuery {
     topicID: { topicNum: 1234 }
     consensusStartTime: { seconds: 0 }
     limit: 9223372036854775806   // Long.MAX_VALUE - 1
   }

2. Observe in server logs: repeated "Executing query" entries with no LIMIT applied.

3. In the database, observe queries of the form:
   SELECT * FROM topic_message WHERE topic_id = 1234
   AND consensus_timestamp >= 0
   ORDER BY consensus_timestamp ASC
   -- no LIMIT clause

4. With a topic containing millions of messages, the server JVM heap is
   exhausted within seconds. Multiple concurrent connections accelerate OOM.

Expected (vulnerable) behavior:
- Server issues unlimited DB queries repeatedly until OOM or timeout.

Expected (fixed) behavior:
- Request rejected at validation with "limit must be <= MAX_ALLOWED" or
  the cast is clamped so pageSize remains positive and bounded by maxPageSize.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-73)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

        if (query.hasTopicID()) {
            filter.topicId(EntityId.of(query.getTopicID()));
        }

        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }

        if (query.hasConsensusEndTime()) {
            long endTime = convertTimestamp(query.getConsensusEndTime());
            filter.endTime(endTime);
        }

        return filter.build();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-26)
```java
    @Min(0)
    private long limit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-62)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
                .doOnCancel(context::onComplete)
                .doOnComplete(context::onComplete)
                .doOnNext(context::onNext);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-57)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```
