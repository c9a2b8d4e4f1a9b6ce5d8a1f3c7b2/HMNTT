### Title
Integer Overflow in `poll()` Causes Unbounded Database Queries and Non-Terminating Poll Loop via Crafted `limit` Value

### Summary
An unprivileged gRPC client can supply a `limit` value of `2147483648L` (Integer.MAX_VALUE + 1) in a `ConsensusTopicQuery`. Inside `PollingTopicMessageRetriever.poll()`, an unchecked narrowing cast from `long` to `int` overflows to `Integer.MIN_VALUE`, which propagates as a negative `limit` into a rebuilt `TopicMessageFilter`. Because `hasLimit()` tests `limit > 0`, the negative value causes the guard to return `false`, so `findByFilter` issues an **unbounded** database query with no `LIMIT` clause. Simultaneously, `isComplete()` evaluates against the original (large) limit and never fires, keeping the polling loop alive for the full 60-second timeout while repeatedly executing unlimited DB queries.

### Finding Description

**Entry point** — `ConsensusController.toFilter()`: [1](#0-0) 

`query.getLimit()` is a protobuf `uint64` mapped to Java `long`. Any value ≥ 0 passes the only constraint on `TopicMessageFilter.limit`: [2](#0-1) 

There is no `@Max` bound, so `2147483648L` is accepted.

**Overflow** — `PollingTopicMessageRetriever.poll()` lines 68–71: [3](#0-2) 

With `filter.getLimit() = 2147483648L` and `context.getTotal().get() = 0`:
- `(int)(2147483648L − 0)` → `(int)(2147483648L)` → **`-2147483648`** (Integer.MIN_VALUE, two's-complement wrap)
- `Math.min(-2147483648, 1000)` → **`-2147483648`** (negative wins)

**Negative limit propagated into rebuilt filter** — line 75: [4](#0-3) 

`toBuilder().limit(pageSize)` is a direct Lombok builder call; Spring's `@Validated` proxy is **not** invoked, so `@Min(0)` is never checked. `newFilter.limit` is stored as `−2147483648L`.

**`hasLimit()` silently disables the DB row cap**: [5](#0-4) 

`−2147483648L > 0` is `false`, so `hasLimit()` returns `false`.

**`findByFilter` skips `setMaxResults` entirely**: [6](#0-5) 

`setMaxResults` is **never called**. The JPA query executes with no `LIMIT` clause and returns every row for the topic.

**`isComplete()` never fires** — evaluated against the original filter: [7](#0-6) 

`filter.getLimit() == total.get()` requires `total` to reach `2147483648` — effectively never. For the throttled path, `pageSize.get() < maxPageSize` is also false when the unbounded query returns many rows, so `isComplete()` returns `false` every iteration.

**Retry amplifier** — line 58: [8](#0-7) 

Any transient DB error during the unlimited query triggers `Retry.backoff(Long.MAX_VALUE, ...)`, retrying indefinitely.

**Note on the question's specific claim**: The question hypothesises that `setMaxResults()` is called with the negative value and throws `IllegalArgumentException`. That specific path does **not** occur — the `hasLimit()` guard at line 51 of `TopicMessageRepositoryCustomImpl` prevents `setMaxResults` from being reached. The actual impact is the unbounded query and non-terminating loop described above.

### Impact Explanation
Each malicious subscription causes repeated full-table scans on `topic_message` (no `LIMIT`) at the configured polling interval (default 2 s) for the full timeout window (default 60 s) — approximately 30 unlimited queries per connection. With many concurrent connections this constitutes a database-level DoS. Because the polling loop holds a scheduler thread and a DB connection for the entire timeout, resource exhaustion (thread pool, connection pool) is also reachable. Gossip/HCS message delivery to legitimate subscribers sharing the same node is degraded or blocked.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is unauthenticated and publicly reachable on any mirror node. The attacker needs only to craft a `ConsensusTopicQuery` with `limit = 2147483648` (one field, trivially set via any gRPC client or `grpcurl`). No special knowledge, credentials, or timing is required. The attack is repeatable and scriptable.

### Recommendation
1. **Add an upper-bound constraint** on `TopicMessageFilter.limit`, e.g. `@Max(Long.MAX_VALUE)` is insufficient — add a domain-specific cap such as `@Max(Integer.MAX_VALUE)` or a configurable property-backed maximum.
2. **Replace the unsafe narrowing cast** in `poll()` with a safe clamp:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = (int) Math.min(remaining, Integer.MAX_VALUE);
   ```
3. **Validate the rebuilt filter** before passing it to `findByFilter`, or assert `pageSize > 0` before building `newFilter`.
4. Apply the same fix to the identical pattern in `PollingTopicListener.poll()`: [9](#0-8) 

### Proof of Concept
```bash
# Using grpcurl against a running mirror-node gRPC endpoint
grpcurl -plaintext \
  -d '{
    "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1},
    "consensusStartTime": {"seconds": 0},
    "limit": 2147483648
  }' \
  localhost:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Expected (vulnerable) behaviour**:
1. `poll()` computes `(int)(2147483648L − 0) = −2147483648`.
2. `newFilter.limit = −2147483648L`; `hasLimit()` returns `false`.
3. `findByFilter` issues `SELECT * FROM topic_message WHERE topic_id = ? AND consensus_timestamp >= ?` with **no LIMIT clause**.
4. `isComplete()` returns `false` every 2 s for 60 s; ~30 unlimited queries execute.
5. DB CPU/IO spikes; legitimate subscribers on the same node experience latency or stalls.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L58-58)
```java
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-57)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```
