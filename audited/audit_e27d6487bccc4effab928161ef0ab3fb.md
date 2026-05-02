### Title
Unbounded Indefinite gRPC Subscriptions Enable Resource Exhaustion DoS via PollingTopicListener

### Summary
Any unauthenticated client can open an unlimited number of gRPC `subscribeTopic` calls with no `consensusEndTime` and no `limit`, causing `PollingTopicListener.listen()` to create a Reactor `Flux` that polls the database indefinitely via `RepeatSpec.times(Long.MAX_VALUE)`. Because no global connection cap, no per-IP subscription limit, and no authentication exist on the gRPC endpoint, an attacker can flood the server with such subscriptions, exhausting database connections, the `boundedElastic` scheduler thread pool, and OS file descriptors, denying service to legitimate consumers.

### Finding Description

**Exact code path:**

`PollingTopicListener.listen()` unconditionally schedules an infinite polling loop:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java, lines 38-43
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))
```

`RepeatSpec.times(Long.MAX_VALUE)` fires a new `poll()` call every `interval` (default 500 ms) for effectively forever. The loop only terminates if the subscriber cancels or a limit/endTime causes the downstream `Flux` to complete.

**Why no endTime = no termination:**

`TopicMessageFilter.endTime` is a nullable `Long` with no `@NotNull` constraint:
```java
// grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java, line 23
private Long endTime;
```

When `endTime == null`, `TopicMessageServiceImpl.pastEndTime()` returns `Flux.never()`:
```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java, lines 123-126
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();
    }
```

And `TopicContext.isComplete()` always returns `false`:
```java
// lines 203-205
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;
    }
```

Similarly, `limit` defaults to `0` (no limit), so `filter.hasLimit()` is false and `flux.take()` is never applied.

**Why existing guards are insufficient:**

The only server-side concurrency control is `maxConcurrentCallsPerConnection = 5` (default):
```java
// grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java, line 14
private int maxConcurrentCallsPerConnection = 5;
```

This is a *per-connection* limit. An attacker opens N TCP connections, each carrying 5 streams = 5N indefinite subscriptions. There is no:
- Global connection count cap (`maxInboundConnections` is never set in `GrpcConfiguration`)
- Per-IP connection or subscription rate limit
- Authentication/authorization on `ConsensusController.subscribeTopic()`
- Maximum total subscriber enforcement (`subscriberCount` in `TopicMessageServiceImpl` is a metrics gauge only, never checked against a ceiling)
- gRPC keepAlive / `maxConnectionAge` / `maxConnectionIdle` to reclaim idle streams

Each active subscription fires `topicMessageRepository.findByFilter()` every 500 ms, consuming a database connection from the pool for the duration of the query.

### Impact Explanation

With enough open subscriptions the following resources are exhausted:

1. **Database connection pool** – every 500 ms each subscription issues a DB query. With a typical pool of 10–20 connections and hundreds of concurrent subscriptions, the pool is saturated; legitimate importer and REST queries time out.
2. **`boundedElastic` thread pool** – `PollingTopicListener` owns a single `Schedulers.boundedElastic()` instance shared across all subscriptions. Its default thread cap is `10 × availableProcessors`. Saturating it stalls all polling tasks, including those of legitimate subscribers.
3. **OS file descriptors** – each gRPC stream holds at least one FD. Exhausting the per-process FD limit (commonly 1024 soft / 65536 hard) prevents new TCP connections from being accepted, blocking all legitimate clients.

The net effect is a complete denial of service to fee-update consumers and any other gRPC or REST client sharing the same process.

### Likelihood Explanation

The attack requires no credentials, no on-chain account, and no special knowledge beyond the publicly documented gRPC endpoint and protobuf schema (published in the repository). A single attacker machine with a modest number of TCP connections (e.g., 200 connections × 5 streams = 1000 indefinite subscriptions) is sufficient to exhaust a typical database pool. The attack is trivially scriptable with `grpcurl` or any gRPC client library and is fully repeatable.

### Recommendation

1. **Enforce a global maximum subscriber count** – check `subscriberCount` against a configurable ceiling in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP / per-connection subscription rate limiting** – use a gRPC `ServerInterceptor` to track and cap streams per remote address.
3. **Set `maxConnectionAge` and `maxConnectionIdle`** in `GrpcConfiguration` via `NettyServerBuilder` to reclaim long-lived idle connections.
4. **Require a maximum `endTime` or `limit`** – reject subscriptions where both `endTime` and `limit` are absent, or enforce a server-side maximum subscription duration.
5. **Add `maxInboundConnections`** to `NettyServerBuilder` to cap total simultaneous TCP connections.

### Proof of Concept

```bash
# Open 200 parallel indefinite subscriptions (no endTime, no limit)
# Each connection carries 5 streams (maxConcurrentCallsPerConnection default)
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 800}}'  \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
# Result: DB connection pool exhausted within seconds;
# subsequent legitimate subscribeTopic calls hang or fail with UNAVAILABLE.
```

Preconditions: network access to the gRPC port (default 5600); no credentials required. The `topicNum` must correspond to an existing topic (or `checkTopicExists=false`).