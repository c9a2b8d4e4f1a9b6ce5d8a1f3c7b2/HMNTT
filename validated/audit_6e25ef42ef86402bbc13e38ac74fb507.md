All code references check out against the actual source. Here is the audit result:

---

# Audit Report

## Title
Integer Overflow in `PollingTopicListener.poll()` Bypasses DB Page Size Cap, Enabling Unbounded Query DoS

## Summary
An unauthenticated gRPC client can supply `limit = Long.MAX_VALUE` in a `ConsensusTopicQuery`. A narrowing `(int)` cast in `PollingTopicListener.poll()` wraps this to `-1`, which causes `hasLimit()` to return `false` in the repository layer, removing the `setMaxResults` guard entirely and allowing the database to return every matching row on every poll cycle.

## Finding Description

**Step 1 — No upper-bound validation at the entry point.**

`ConsensusController.toFilter()` copies the proto `uint64 limit` field directly into `TopicMessageFilter` with no ceiling check: [1](#0-0) 

`TopicMessageFilter.limit` carries only `@Min(0)` — there is no `@Max` constraint, so `Long.MAX_VALUE` passes bean validation: [2](#0-1) 

**Step 2 — Integer overflow in `PollingTopicListener.poll()`.** [3](#0-2) 

With `filter.getLimit() = Long.MAX_VALUE` and `context.getCount() = 0`:
- `Long.MAX_VALUE - 0 = 0x7FFFFFFFFFFFFFFF`
- `(int) 0x7FFFFFFFFFFFFFFF` → lower 32 bits = `0xFFFFFFFF` = **`-1`** (two's-complement)
- `Math.min(-1, 5000) = -1`
- `newFilter` is built with `limit = -1`

The `maxPageSize` default of 5000 is confirmed: [4](#0-3) 

**Step 3 — Guard bypass in `TopicMessageRepositoryCustomImpl.findByFilter()`.** [5](#0-4) 

`hasLimit()` is defined as `return limit > 0`: [6](#0-5) 

With `limit = -1`, `hasLimit()` returns `false`, `setMaxResults` is never called, and the JPA query fetches **all** rows matching the topic/timestamp predicate.

## Impact Explanation
Every poll cycle (default every 500 ms per `ListenerProperties.interval`) issues an unbounded `SELECT *` against the `topic_message` table for the targeted topic. On a busy topic with millions of rows, this exhausts database memory, connection pool resources, and JVM heap on the mirror node. A single persistent gRPC subscription is sufficient to degrade or crash the service for all other subscribers. [7](#0-6) 

## Likelihood Explanation
The gRPC endpoint is publicly reachable with no authentication. The `ConsensusTopicQuery` proto field `uint64 limit` accepts the full 64-bit range; setting it to `Long.MAX_VALUE` requires only a standard gRPC client (e.g., `grpcurl`). No special privileges, tokens, or knowledge of internal state are required. The attack is trivially repeatable and persistent for the lifetime of the subscription. [8](#0-7) 

## Recommendation
Apply a cap on the `limit` field before it enters `TopicMessageFilter`. The simplest fix is to clamp the value in `ConsensusController.toFilter()`:

```java
// In ConsensusController.toFilter()
long rawLimit = query.getLimit();
long safeLimit = (rawLimit <= 0) ? 0 : Math.min(rawLimit, Integer.MAX_VALUE);
final var filter = TopicMessageFilter.builder().limit(safeLimit);
```

Additionally, add a `@Max(Integer.MAX_VALUE)` constraint to `TopicMessageFilter.limit` as a defense-in-depth measure, and consider replacing the unchecked `(int)` narrowing cast in `PollingTopicListener.poll()` with `Math.toIntExact()` or an explicit clamp so that any future overflow is caught at the source rather than silently producing a negative value. [9](#0-8) 

## Proof of Concept

```bash
# Using grpcurl against a running mirror node gRPC endpoint
grpcurl -plaintext \
  -d '{
    "topicID": {"topicNum": 1},
    "consensusStartTime": {"seconds": 0},
    "limit": 9223372036854775807
  }' \
  localhost:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

This single subscription causes `PollingTopicListener.poll()` to compute `pageSize = -1`, bypasses `setMaxResults` in `TopicMessageRepositoryCustomImpl.findByFilter()`, and issues a full table scan every 500 ms for the lifetime of the connection. [10](#0-9)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-59)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L25-26)
```java
    @Min(32)
    private int maxPageSize = 5000;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L28-30)
```java
    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
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
