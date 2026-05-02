### Title
Unbounded `limit=Long.MAX_VALUE` Causes Indefinite gRPC Stream Hold, Enabling Resource Exhaustion DoS

### Summary
An unprivileged user can submit a `ConsensusTopicQuery` with `limit` set to `Long.MAX_VALUE` and no `endTime`. Because `TopicMessageFilter` enforces only `@Min(0)` on the `limit` field (no upper bound), `hasLimit()` returns `true`, and `flux.take(Long.MAX_VALUE)` is invoked — which in Reactor never terminates by count. Combined with the absence of a server-side stream age limit, the gRPC stream is held open indefinitely, consuming a connection slot and associated resources. An attacker opening many such connections can exhaust server capacity and starve legitimate subscribers.

### Finding Description

**Exact code path:**

1. `ConsensusController.toFilter()` passes `query.getLimit()` (a raw `long`) directly to `TopicMessageFilter.builder().limit(...)` with no upper-bound check. [1](#0-0) 

2. `TopicMessageFilter.limit` is validated only with `@Min(0)` — `Long.MAX_VALUE` passes this constraint. [2](#0-1) 

3. `hasLimit()` returns `limit > 0`, which is `true` for `Long.MAX_VALUE`. [3](#0-2) 

4. In `subscribeTopic()`, `flux.take(Long.MAX_VALUE)` is applied — Reactor's `take(n)` with `n = Long.MAX_VALUE` never terminates by count. [4](#0-3) 

5. With no `endTime` supplied, `pastEndTime()` returns `Flux.never()`, so the `takeUntilOther` guard never fires. [5](#0-4) 

6. `TopicContext.isComplete()` always returns `false` when `endTime == null`. [6](#0-5) 

7. The live flux (`incomingMessages`) also propagates `Long.MAX_VALUE` as its own limit, keeping the listener alive indefinitely. [7](#0-6) 

**Root cause:** No maximum value is enforced on `TopicMessageFilter.limit`. The `hasLimit()` predicate treats `Long.MAX_VALUE` as a legitimate finite limit, but `Flux.take(Long.MAX_VALUE)` is operationally infinite.

**Failed assumption:** The code assumes that if `hasLimit()` is `true`, the stream will eventually terminate by count. This assumption breaks at `Long.MAX_VALUE`.

### Impact Explanation
Each open stream holds a gRPC connection slot, a Reactor subscription, and associated thread/scheduler resources. `NettyProperties.maxConcurrentCallsPerConnection` is set to 5, but this is per-connection — an attacker opens many TCP connections, each with 5 streams, multiplying the impact. The `RetrieverProperties.timeout` (60 s) applies only to the historical polling retriever, not to the live `topicListener.listen()` path. There is no `maxConnectionAge` configured. Legitimate subscribers (e.g., applications monitoring fund-critical HCS topics) are starved of server capacity, causing missed or delayed messages. [8](#0-7) [9](#0-8) 

### Likelihood Explanation
No authentication or authorization is required to call `subscribeTopic`. Any network-reachable client can send a `ConsensusTopicQuery` protobuf with `limit = 9223372036854775807` (the max `int64` value). The attack is trivially scriptable, repeatable, and requires no special knowledge beyond the public Hedera gRPC API specification. A single attacker with modest bandwidth can open hundreds of persistent streams.

### Recommendation
1. **Add `@Max` on `TopicMessageFilter.limit`** — enforce a reasonable server-side maximum (e.g., `@Max(10_000_000)`) so no single subscriber can request an operationally infinite stream. [2](#0-1) 

2. **Enforce a maximum stream duration** — add `maxConnectionAge` / `maxConnectionAgeGrace` to `NettyProperties` and wire them into the gRPC server configuration so no stream can live beyond a configurable wall-clock limit regardless of `limit` value. [10](#0-9) 

3. **Cap total concurrent subscribers** — add a server-wide subscriber ceiling (not just per-connection) checked in `subscribeTopic()` against `subscriberCount`. [11](#0-10) 

### Proof of Concept
```
# Using grpcurl (no auth required)
grpcurl -plaintext \
  -d '{
    "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1},
    "consensusStartTime": {"seconds": 0},
    "limit": 9223372036854775807
  }' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

Repeat this in a loop across many parallel processes. Each call:
1. Passes `@Min(0)` validation (9223372036854775807 ≥ 0).
2. `hasLimit()` returns `true` → `flux.take(Long.MAX_VALUE)` is applied.
3. No `endTime` → `pastEndTime()` = `Flux.never()`, `isComplete()` = `false`.
4. Stream stays open indefinitely, holding resources.
5. After enough parallel streams, legitimate subscribers receive errors or timeouts.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L56-56)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L115-116)
```java
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L28-28)
```java
    private Duration timeout = Duration.ofSeconds(60L);
```
