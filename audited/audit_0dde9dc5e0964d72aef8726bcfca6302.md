### Title
Integer Overflow in `PollingTopicListener.poll()` Bypasses Row Limit, Enabling Unlimited Database Query via Crafted gRPC `limit`

### Summary
In `PollingTopicListener.poll()`, the expression `(int)(filter.getLimit() - context.getCount().get())` performs an unchecked narrowing cast from `long` to `int`. When a client supplies a `limit` value greater than `Integer.MAX_VALUE` (e.g., `2,147,483,648`), the cast silently overflows to a negative integer. Because `TopicMessageFilter.hasLimit()` returns `false` for any value ≤ 0, the downstream `findByFilter()` call omits `setMaxResults()` entirely, causing the JPA query to return every matching row in the table with no bound.

### Finding Description

**Exact code path:**

`PollingTopicListener.java`, `poll()`, lines 54–61:
```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())   // ← overflow here
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());  // min(negative, 5000) = negative
...
var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();  // limit = -2147483648
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

`TopicMessageFilter.java`, line 39–41:
```java
public boolean hasLimit() {
    return limit > 0;   // returns FALSE for negative pageSize
}
```

`TopicMessageRepositoryCustomImpl.java`, lines 51–53:
```java
if (filter.hasLimit()) {          // FALSE → setMaxResults() is never called
    typedQuery.setMaxResults((int) filter.getLimit());
}
```

**Root cause:** The code assumes `filter.getLimit()` fits in a Java `int`. The gRPC proto field is `uint64 limit`, which Java represents as a `long`. `TopicMessageFilter.limit` carries only a `@Min(0)` constraint with no upper bound, so any positive `long` value passes validation. When `filter.getLimit()` ≥ `2^31` and `context.getCount().get()` is 0, the subtraction result is ≥ `2^31`, which overflows to a negative `int` on the narrowing cast. `Math.min(negative, maxPageSize)` returns the negative value. The Lombok `toBuilder()` call does not re-trigger Bean Validation, so the negative limit is stored in `newFilter`. `hasLimit()` then returns `false`, and `setMaxResults()` is never invoked, leaving the JPA query unbounded.

**Why existing checks fail:**
- `@Min(0)` on `TopicMessageFilter.limit` only rejects negative *input*; it does not prevent overflow of a large positive value during the cast.
- `hasLimit()` is designed to distinguish "no limit" (0) from "has limit" (>0), but a negative overflow value is indistinguishable from "no limit" by this check.
- The Lombok builder used in `poll()` does not invoke Spring/Bean Validation, so the negative value is never rejected.

### Impact Explanation
Every poll cycle (default: every 500 ms) issues a JPA query with no `LIMIT` clause against the `topic_message` table. On a production node with millions of rows, each poll loads the entire result set into the JVM heap. This causes:
- **Memory exhaustion / OOM** on the mirror node JVM.
- **Database overload**: repeated full-table scans on a high-frequency timer.
- **Denial of service** for all other gRPC subscribers sharing the same node.
- Potential **data exfiltration**: all topic messages for the subscribed topic are streamed to the attacker's gRPC connection.

Severity: **High** (DoS + data exposure).

### Likelihood Explanation
The attack requires:
1. The mirror node to be configured with `hiero.mirror.grpc.listener.type = POLL` (not the default `REDIS`). This is a non-default configuration, reducing exposure.
2. The attacker to open a gRPC `subscribeTopic` stream with `limit` set to any value ≥ `2,147,483,648` — a single crafted protobuf message, requiring no credentials or elevated privileges.

Any unauthenticated gRPC client can send this value. The attack is trivially repeatable and requires no prior knowledge of the system beyond the public gRPC API. Operators who explicitly choose `POLL` mode (e.g., for Redis-free deployments) are fully exposed.

### Recommendation
1. **Guard the cast** in `poll()` with an explicit range check before narrowing:
   ```java
   long remaining = filter.getLimit() - context.getCount().get();
   int limit = (remaining > Integer.MAX_VALUE || remaining < 0)
               ? Integer.MAX_VALUE
               : (int) remaining;
   ```
2. **Add `@Max(Integer.MAX_VALUE)` (or a domain-appropriate maximum) to `TopicMessageFilter.limit`** so oversized values are rejected at the API boundary before reaching listener logic.
3. Apply the same fix to the identical pattern in `PollingTopicMessageRetriever.poll()` (lines 68–70), which contains the same `(int)(filter.getLimit() - context.getTotal().get())` cast.

### Proof of Concept
**Precondition:** Mirror node running with `hiero.mirror.grpc.listener.type=POLL`.

**Steps:**
1. Construct a gRPC `ConsensusTopicQuery` protobuf message:
   - `topicID`: any valid topic ID present in the database
   - `consensusStartTime`: epoch (0)
   - `limit`: `2147483648` (= `Integer.MAX_VALUE + 1`)
2. Open a streaming gRPC call to `ConsensusService/subscribeTopic` with this message.
3. The mirror node maps `limit=2147483648` into `TopicMessageFilter.limit` (passes `@Min(0)`).
4. `PollingTopicListener.poll()` computes `(int)(2147483648L - 0L)` = `-2147483648`.
5. `Math.min(-2147483648, 5000)` = `-2147483648`; `newFilter.limit = -2147483648`.
6. `hasLimit()` returns `false`; `setMaxResults()` is not called.
7. JPA executes `SELECT * FROM topic_message WHERE topic_id = ? AND consensus_timestamp >= ?` with **no LIMIT clause**.
8. All rows are loaded and streamed back. This query repeats every 500 ms until the connection is closed.