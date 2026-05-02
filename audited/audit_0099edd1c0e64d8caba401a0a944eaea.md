### Title
Integer Narrowing Overflow in `poll()` Bypasses DB Query Limit, Enabling Unbounded Query DoS

### Summary
In `PollingTopicMessageRetriever.poll()`, a user-controlled `limit` of `Long.MAX_VALUE` (a valid `uint64` gRPC field value that passes `@Min(0)` validation) is narrowed to `int` via an unchecked cast, producing `-1`. This negative value causes `hasLimit()` to return `false` on the internally-built filter, removing the `setMaxResults` guard in `findByFilter()` and issuing an unbounded `SELECT *` against the topic message table — a non-network DoS reachable by any unauthenticated caller.

### Finding Description

**Entry point — no upper-bound check on `limit`:**

`ConsensusController.toFilter()` maps the proto `uint64 limit` field directly to `TopicMessageFilter.limit` with no cap: [1](#0-0) 

The proto definition confirms `limit` is `uint64`, so any value `0 … 2^64-1` is wire-legal: [2](#0-1) 

**Validation passes for `Long.MAX_VALUE`:**

`TopicMessageFilter.limit` carries only `@Min(0)`: [3](#0-2) 

`Long.MAX_VALUE` satisfies `>= 0`, so `@Valid` on `subscribeTopic` does not reject it: [4](#0-3) 

**Overflow in `poll()`:**

```
filter.getLimit()          = Long.MAX_VALUE  (0x7FFFFFFFFFFFFFFF)
context.getTotal().get()   = 0               (first poll)
difference                 = 0x7FFFFFFFFFFFFFFF
(int) 0x7FFFFFFFFFFFFFFF   = 0xFFFFFFFF = -1  ← negative
Math.min(-1, maxPageSize)  = -1
``` [5](#0-4) 

**Internal filter built with `limit = -1` bypasses `hasLimit()`:**

`filter.toBuilder().limit(-1).build()` is a raw Lombok builder call — Spring's `@Validated` AOP interceptor is never invoked, so `@Min(0)` is not enforced here: [6](#0-5) 

`hasLimit()` returns `limit > 0`; with `limit = -1` this is `false`: [7](#0-6) 

**`setMaxResults` is never called — unbounded query executes:** [8](#0-7) 

`getResultList()` is synchronous and loads the entire result set into the JVM heap before any reactive timeout can cancel it: [9](#0-8) 

**Same pattern exists in `PollingTopicListener.poll()`:** [10](#0-9) 

**`isComplete()` does not save the situation:**

With `filter.getLimit() = Long.MAX_VALUE`, `limitHit` is `Long.MAX_VALUE == total.get()` — practically never true. For throttled mode the only other exit is `pageSize.get() < maxPageSize`, which only fires *after* the unbounded query already returns: [11](#0-10) 

### Impact Explanation
A single gRPC `subscribeTopic` call with `limit = Long.MAX_VALUE` causes the mirror node to issue a `SELECT * FROM topic_message WHERE topic_id = ?` with no `LIMIT` clause, loading potentially millions of rows into JVM heap. On a busy topic (e.g., a high-throughput HCS topic), this causes OOM or severe GC pressure, crashing or stalling the gRPC service for all subscribers. The `retrieverProperties.getTimeout()` wraps the reactive stream but cannot interrupt the synchronous `getResultList()` call mid-execution. Multiple concurrent attackers amplify the effect.

### Likelihood Explanation
The gRPC endpoint is publicly accessible with no authentication required. The attacker needs only a valid `topicId` (trivially discoverable from the public ledger) and a single gRPC call with `limit` set to `9223372036854775807`. No special privileges, no rate-limit bypass, and no prior knowledge of internals is needed. The attack is trivially repeatable with `grpcurl` or any gRPC client library.

### Recommendation
1. **Add an upper-bound cap in `ConsensusController.toFilter()`** before building the filter — clamp `query.getLimit()` to a configured maximum (e.g., `retrieverProperties.getMaxPageSize()`).
2. **Replace the unsafe narrowing cast** in `poll()` with a safe computation:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = (remaining > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int) remaining;
   ```
3. **Add `@Max` constraint** on `TopicMessageFilter.limit` to enforce a server-side ceiling at the validation layer.
4. Apply the same fix to `PollingTopicListener.poll()`.

### Proof of Concept

**Preconditions:** Mirror node running, any valid `topicId` known (e.g., `41110`).

```bash
grpcurl -plaintext \
  -d '{
    "topicID": {"topicNum": 41110},
    "consensusStartTime": {"seconds": 0},
    "limit": 9223372036854775807
  }' \
  localhost:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Trigger path:**
1. `ConsensusController.toFilter()` sets `filter.limit = Long.MAX_VALUE` — passes `@Min(0)` validation.
2. `PollingTopicMessageRetriever.poll()` computes `(int)(Long.MAX_VALUE - 0) = -1`.
3. `Math.min(-1, maxPageSize) = -1`.
4. `newFilter.limit(-1)` → `hasLimit()` returns `false`.
5. `findByFilter()` skips `setMaxResults` → unbounded `SELECT *` executes synchronously.
6. JVM heap fills with all topic messages; GC pressure or OOM crash follows.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-57)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L25-25)
```text
    uint64 limit = 4;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageService.java (L12-12)
```java
    Flux<TopicMessage> subscribeTopic(@Valid TopicMessageFilter filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-71)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L75-75)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-57)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```
