### Title
Unbounded Concurrent Subscription DoS via Missing Global Rate Limit in `retrieve()`

### Summary
`PollingTopicMessageRetriever.retrieve()` contains no per-IP, per-user, or global subscription count enforcement. The only defense — `maxConcurrentCallsPerConnection = 5` — is a per-TCP-connection limit trivially bypassed by opening multiple connections. An unauthenticated attacker can open arbitrarily many connections and flood the server with concurrent polling subscriptions, exhausting the database connection pool and the `boundedElastic` scheduler, denying service to all legitimate subscribers.

### Finding Description

**Code path:**

`retrieve()` in `PollingTopicMessageRetriever.java` (lines 45–63): [1](#0-0) 

Each invocation unconditionally creates a new `PollingContext` and starts a `Flux` that:
- Polls the database via `topicMessageRepository.findByFilter()` on every tick
- In throttled mode (`numRepeats = Long.MAX_VALUE`): polls every 2 seconds indefinitely until historical catch-up
- Retries on any error with `Retry.backoff(Long.MAX_VALUE, ...)` — holding resources through transient DB failures
- Uses a single shared `Schedulers.boundedElastic()` scheduler instance across all subscriptions

**The only server-side guard** is `maxConcurrentCallsPerConnection = 5`: [2](#0-1) 

Applied in `GrpcConfiguration`: [3](#0-2) 

No `maxConnectionsTotal`, no per-IP connection limit, no `permitKeepAliveWithoutCalls`, and no global connection count is configured. The `subscriberCount` field in `TopicMessageServiceImpl` is a Micrometer gauge only — it has zero enforcement logic: [4](#0-3) 

**Root cause:** `retrieve()` assumes the caller (the gRPC transport layer) enforces connection-level limits sufficient to bound total resource consumption. That assumption fails because the per-connection limit does not bound the total number of connections.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (no authentication required — `ConsensusController.subscribeTopic` has no auth check)
2. On each connection, sends 5 concurrent `subscribeTopic` RPCs with `startTime=0`, `limit=0` (unlimited), targeting any valid topic
3. Each RPC triggers `topicMessageRetriever.retrieve(filter, true)` → `poll()` → `topicMessageRepository.findByFilter()` every 2 seconds
4. With N=200 connections: 1,000 concurrent DB queries every 2 seconds
5. The gRPC DB connection pool (default `statementTimeout=10000ms`) is exhausted; new legitimate subscriptions time out or fail

### Impact Explanation

Exhausting the gRPC service's database connection pool causes all new `subscribeTopic` calls to fail with timeout errors. Existing subscriptions that need DB access (gap recovery via `missingMessages()`, historical retrieval) also fail. The `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` in each attacker subscription means they keep retrying and re-acquiring pool connections even during partial exhaustion, creating a sustained denial of service. The gRPC API becomes completely unavailable to legitimate users. The importer has a separate DB pool so transaction ingestion continues, but the mirror node's public gRPC interface is fully down.

### Likelihood Explanation

No authentication is required. The gRPC port (5600) is publicly exposed per the documented deployment. Opening hundreds of TCP connections is trivial from a single machine or a small botnet. The `grpcurl` tool shown in the project's own documentation makes scripting this trivial. The attack is repeatable and self-sustaining due to `Retry.backoff(Long.MAX_VALUE, ...)`. [5](#0-4) 

### Recommendation

1. **Add a global concurrent-subscription cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold (e.g., 1000).
2. **Add a per-IP concurrent-subscription limit** using a `ConcurrentHashMap<String, AtomicInteger>` keyed on the remote address from the gRPC `Context`, rejecting calls that exceed the per-IP cap.
3. **Configure a total connection limit** on the Netty server builder via `maxConnectionAge` and `maxConnectionIdle` to reclaim idle attacker connections.
4. **Add `maxConcurrentCallsPerConnection` enforcement at the IP level** via a gRPC `ServerInterceptor` that tracks and rejects connections from IPs exceeding a threshold.
5. **Enforce a minimum `startTime`** (e.g., no more than 24h in the past) to bound the duration of each historical retrieval polling loop.

### Proof of Concept

```bash
# Open 200 connections, 5 subscriptions each = 1000 concurrent polling subscriptions
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Verify legitimate subscriber is denied:
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 41110}, "limit": 1}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected: DEADLINE_EXCEEDED or UNAVAILABLE due to DB pool exhaustion
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L45-63)
```java
    public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
        if (!retrieverProperties.isEnabled()) {
            return Flux.empty();
        }

        PollingContext context = new PollingContext(filter, throttled);
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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

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

**File:** docs/grpc/README.md (L14-16)
```markdown
Example invocation using [grpcurl](https://github.com/fullstorydev/grpcurl):

`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```
