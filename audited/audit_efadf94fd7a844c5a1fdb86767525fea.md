Based on my analysis of the code, here is my finding:

---

### Title
Unbounded JPA Query via `limit=0` in `TopicMessageRepositoryCustomImpl.findByFilter()`

### Summary
`TopicMessageFilter` accepts `limit=0` as valid input (enforced only by `@Min(0)`), and `hasLimit()` returns `false` when `limit == 0`. In `TopicMessageRepositoryCustomImpl.findByFilter()`, `setMaxResults` is only called when `hasLimit()` is true, so a `limit=0` filter causes the JPA query to load the entire `topic_message` table for the given topic into heap memory via `getResultList()`. Any unauthenticated gRPC caller can trigger this repeatedly to exhaust server memory and starve other subscribers.

### Finding Description

**Code path:**

`TopicMessageFilter.hasLimit()` — [1](#0-0)  returns `false` when `limit == 0`, and `@Min(0)` explicitly permits `limit=0` as valid. [2](#0-1) 

`TopicMessageRepositoryCustomImpl.findByFilter()` — `setMaxResults` is guarded by `filter.hasLimit()`: [3](#0-2) 

When `hasLimit()` is `false`, `setMaxResults` is never called, and the query executes without any row limit. The result is materialized entirely in memory via `getResultList()`: [4](#0-3) 

`TopicMessageServiceImpl.subscribeTopic()` also skips the reactive `.take()` cap when `hasLimit()` is false: [5](#0-4) 

The `missingMessages()` gap-recovery path builds a new filter from the original via `toBuilder()`, preserving `limit=0`, and calls `topicMessageRetriever.retrieve()` again with no bound: [6](#0-5) 

**Root cause:** The design treats `limit=0` as "no limit" (semantically "unlimited"), but there is no server-side maximum cap to prevent a caller from intentionally requesting unlimited results. The `@Min(0)` constraint validates the field but does not enforce a minimum meaningful value of 1.

**Failed assumption:** The code assumes callers will either provide a positive limit or that the topic will have a manageable number of historical messages. Neither is guaranteed.

### Impact Explanation
An attacker submitting `limit=0` with a `startTime` far in the past causes `getResultList()` to load every historical message for that topic into JVM heap in a single call. On a busy topic with millions of messages, this can exhaust heap memory, trigger GC pressure, and cause OOM errors or severe latency for all other subscribers. Because the gRPC endpoint requires no authentication, this is trivially repeatable by multiple concurrent connections.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication requirement. The `limit` field in the protobuf request maps directly to `TopicMessageFilter.limit`. Setting `limit=0` (or omitting it, since the default is `0` via `long` primitive default) is the default behavior for any client that does not explicitly set a limit. This means even non-malicious clients trigger this path by default, and a malicious actor can trivially exploit it at scale.

### Recommendation
1. **Enforce a server-side maximum page size** in `TopicMessageRepositoryCustomImpl.findByFilter()`: always call `typedQuery.setMaxResults(Math.min(filter.hasLimit() ? (int) filter.getLimit() : MAX_PAGE_SIZE, MAX_PAGE_SIZE))`.
2. **Change `@Min(0)` to `@Min(1)` or treat `limit=0` as requiring a server-enforced cap** rather than "unlimited."
3. **Replace `getResultList().stream()` with a true streaming/cursor approach** (e.g., `ScrollableResults` or paginated queries) to avoid materializing unbounded result sets in heap.
4. Add a configurable `maxLimit` property in `GrpcProperties` and enforce it at the service layer in `TopicMessageServiceImpl.subscribeTopic()`.

### Proof of Concept
1. Connect to the mirror node gRPC endpoint (no credentials required).
2. Send a `subscribeTopic` request with a valid `topicId`, `consensusStartTime` set to epoch (0), and `limit` omitted or set to `0`.
3. `TopicMessageFilter` is built with `limit=0`; `hasLimit()` returns `false`.
4. `topicMessageRetriever.retrieve(filter, true)` calls `findByFilter(filter)`.
5. `setMaxResults` is never called; the JPA query fetches all rows for the topic.
6. `getResultList()` loads the entire result set into heap memory.
7. Repeat with 10–20 concurrent connections targeting a high-volume topic to exhaust heap and deny service to legitimate subscribers.

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L164-168)
```java
        TopicMessageFilter newFilter = topicContext.getFilter().toBuilder()
                .endTime(current.getConsensusTimestamp())
                .limit(numMissingMessages)
                .startTime(last.getConsensusTimestamp() + 1)
                .build();
```
