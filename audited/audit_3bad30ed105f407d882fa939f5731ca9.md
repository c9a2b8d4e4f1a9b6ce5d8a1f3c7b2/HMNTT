### Title
Unbounded gRPC Topic Subscription via Uncapped `limit` Field Enables Indefinite Resource Exhaustion

### Summary
`TopicMessageFilter.limit` is validated only with `@Min(0)` and has no upper bound, allowing any unauthenticated caller to submit `limit = Long.MAX_VALUE` with no `endTime`. The resulting `flux.take(Long.MAX_VALUE)` combined with a `Flux.never()` termination signal keeps the server-side reactive stream open indefinitely. An attacker can open many such subscriptions in parallel, exhausting gRPC worker threads, database listener slots, and memory without any server-side enforcement to stop them.

### Finding Description

**Root cause — no upper bound on `limit`:**

`TopicMessageFilter.java` declares:

```java
@Min(0)
private long limit;
``` [1](#0-0) 

There is no `@Max` constraint. `Long.MAX_VALUE` (9,223,372,036,854,775,807) passes validation.

**`hasLimit()` returns `true` for `Long.MAX_VALUE`:**

```java
public boolean hasLimit() {
    return limit > 0;
}
``` [2](#0-1) 

So `flux.take(Long.MAX_VALUE)` is applied — effectively infinite.

**No time-based termination when `endTime` is absent:**

```java
if (filter.getEndTime() != null) {
    flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
}

if (filter.hasLimit()) {
    flux = flux.take(filter.getLimit());
}
``` [3](#0-2) 

With `endTime = null`, the `takeWhile` branch is skipped entirely.

**`pastEndTime()` returns `Flux.never()` when `endTime` is null:**

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();
    }
    ...
}
``` [4](#0-3) 

The `takeUntilOther(pastEndTime(topicContext))` on line 73 therefore never fires.

**`isComplete()` always returns `false` when `endTime` is null:**

```java
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;
    }
    ...
}
``` [5](#0-4) 

**`subscriberCount` is only a metric — never used to reject connections:**

```java
.doOnSubscribe(s -> subscriberCount.incrementAndGet())
.doFinally(s -> subscriberCount.decrementAndGet())
``` [6](#0-5) 

The counter is exposed as a Micrometer gauge but is never checked before accepting a new subscription. No per-IP, per-user, or global connection cap exists in the gRPC service layer.

**No gRPC-layer throttle for this service:** The `ThrottleConfiguration` and `ThrottleProperties` found in the codebase belong exclusively to the `web3` module; there is no equivalent rate-limiting or connection-limiting bean wired into the `grpc` module.

### Impact Explanation
An attacker who opens N concurrent subscriptions with `limit = Long.MAX_VALUE` and no `endTime` holds N live reactive streams open indefinitely. Each stream retains a gRPC server thread/event-loop slot, a PostgreSQL `LISTEN` channel (via `TopicListener`), and associated heap objects. As N grows, legitimate subscribers are starved of threads and DB connections, causing subscription failures or severe latency for all users of the mirror node's HCS streaming API.

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication requirement. The protobuf `ConsensusTopicQuery.limit` field is a `uint64`, so any client SDK or raw gRPC call can trivially set it to `Long.MAX_VALUE`. The attack requires no special knowledge, no credentials, and is trivially repeatable from a single machine using multiple concurrent gRPC streams.

### Recommendation
1. **Add `@Max` to `TopicMessageFilter.limit`** — enforce a reasonable server-side ceiling (e.g., 10,000 or a configurable property).
2. **Enforce a maximum subscription duration** — add a configurable `maxSubscriptionDuration` to `GrpcProperties` and apply `flux.timeout(maxDuration)` unconditionally in `subscribeTopic()`.
3. **Cap concurrent subscriptions per remote peer** — intercept at the gRPC `ServerInterceptor` level and reject connections that exceed a per-IP or global threshold.
4. **Require `endTime` or a bounded `limit`** — add a cross-field `@AssertTrue` validator that rejects filters where both `endTime == null` and `limit == 0` (or `limit > MAX_ALLOWED`).

### Proof of Concept
```java
// Using the Hedera Java SDK or any gRPC client:
TopicMessageQuery query = new TopicMessageQuery();
query.setTopicId(TopicId.fromString("0.0.1234")); // any valid topic
query.setLimit(Long.MAX_VALUE);                    // no @Max check — passes validation
// endTime intentionally omitted

// Open 500 concurrent streams from a single host:
for (int i = 0; i < 500; i++) {
    query.subscribe(client, msg -> {});
}
// Each stream is held open indefinitely.
// Server subscriberCount climbs; gRPC thread pool and DB listener slots are exhausted.
// Legitimate subscribers receive RESOURCE_EXHAUSTED or hang.
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L79-85)
```java
        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L89-90)
```java
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-131)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }

        return Flux.empty()
                .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                        .withFixedDelay(grpcProperties.getEndTimeInterval()));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-206)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }
```
