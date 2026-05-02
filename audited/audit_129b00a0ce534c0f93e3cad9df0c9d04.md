### Title
Unbounded Historical Scan via Epoch-Zero `consensusStartTime` in gRPC `subscribeTopic`

### Summary
Any unauthenticated gRPC client can set `consensusStartTime` to Unix epoch (`seconds=0, nanos=0`) in a `ConsensusTopicQuery`. The `toFilter()` method in `ConsensusController` converts this to `startTime=0`, which passes all existing validation checks in `TopicMessageFilter`. The resulting subscription drives `PollingTopicMessageRetriever` to repeatedly query the database from the beginning of the topic's entire history for up to 60 seconds per subscription, with no per-client rate limiting on the gRPC API, enabling a griefing attack that saturates DB I/O and degrades service for all users.

### Finding Description

**Exact code path:**

`ConsensusController.toFilter()` ( [1](#0-0) ) checks `query.hasConsensusStartTime()` and calls `convertTimestamp()`. For `{seconds:0, nanos:0}`, `convertTimestamp()` returns `0` (0 < 9223372035L, so it falls through to `DomainUtils.timestampInNanosMax` which returns 0). [2](#0-1) 

**Validation failure:**

`TopicMessageFilter` has two guards on `startTime`:
- `@Min(0)` — value `0` satisfies `>= 0`, passes. [3](#0-2) 
- `isValidStartTime()` — checks only `startTime <= DomainUtils.now()`. Unix epoch `0` is always before now, so this passes unconditionally. [4](#0-3) 

There is no minimum lookback window enforced.

**DB query impact:**

`TopicMessageRepositoryCustomImpl.findByFilter()` builds: `WHERE topic_id = ? AND consensus_timestamp >= 0 ORDER BY consensus_timestamp ASC LIMIT <pageSize>`. [5](#0-4) 

For a topic with millions of messages, this index range scan starts at the very beginning of chain history.

**Polling amplification:**

`PollingTopicMessageRetriever.retrieve()` in throttled mode sets `numRepeats = Long.MAX_VALUE` and polls every 2 seconds with `maxPageSize=1000`, bounded only by a 60-second timeout. [6](#0-5) 

`isComplete()` in throttled mode returns `true` only when the last page returned fewer than `maxPageSize` rows. [7](#0-6) 

For a topic with a large history, every page is full (1000 rows), so `isComplete()` never returns `true` until the 60-second timeout fires — yielding ~30 DB queries per subscription, each reading 1000 rows from timestamp 0.

**No gRPC-level rate limiting:**

The gRPC module has no per-IP or global request rate limiter. The only concurrency control is `maxConcurrentCallsPerConnection = 5` (per connection). [8](#0-7) 

An attacker opens many connections (each with 5 streams), multiplying the DB load linearly. The web3 throttle (`ThrottleConfiguration`) does not apply to the gRPC service. [9](#0-8) 

### Impact Explanation

Each malicious subscription causes ~30 paginated DB queries over 60 seconds, each reading 1000 rows from the start of a topic's history. With N connections × 5 streams each, the attacker generates 150N DB queries per minute, all performing large index range scans. This saturates DB I/O, increases query latency for legitimate users, and can cause the retriever timeout to cascade into subscriber errors. The `db.statementTimeout = 10000ms` does not help because each individual page query completes well within 10 seconds — the harm is cumulative across repeated polls.

### Likelihood Explanation

The attack requires no authentication, no special privileges, and no knowledge beyond the public gRPC proto definition. The `ConsensusTopicQuery` proto field `consensusStartTime` is documented and standard. Any client library (e.g., the Hedera Java/Go/JS SDK) can set it to epoch zero in one line. The attack is trivially repeatable and scriptable. A single attacker with a modest number of connections can sustain continuous DB pressure indefinitely by reconnecting after the 60-second timeout.

### Recommendation

1. **Enforce a minimum `startTime` lookback window** in `TopicMessageFilter.isValidStartTime()`: reject requests where `startTime < (DomainUtils.now() - maxLookbackNanos)`, where `maxLookbackNanos` is a configurable property (e.g., 30 days).
2. **Add per-IP or per-connection rate limiting** to the gRPC layer (e.g., via a gRPC interceptor using a token-bucket per remote address), analogous to the web3 `ThrottleConfiguration`.
3. **Require a non-zero `limit`** when `startTime` is far in the past, or cap the maximum number of retriever polls per subscription.
4. **Add a global concurrent-subscription cap** (not just per-connection) to bound total DB load.

### Proof of Concept

```python
# Using grpc Python library and hedera proto stubs
import grpc
from hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from hederahashgraph.api.proto.java import basic_types_pb2, timestamp_pb2

channel = grpc.insecure_channel("mirror-node-grpc-host:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

# Set consensusStartTime to Unix epoch (seconds=0, nanos=0)
query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=<popular_topic_id>),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    # No limit set — forces full historical scan
)

# Open many concurrent streams across multiple connections
for msg in stub.subscribeTopic(query):
    pass  # Attacker discards results; DB is already loaded
```

Repeat across many connections. Each stream drives ~30 DB queries over 60 seconds reading from `consensus_timestamp >= 0` for the target topic. Scale connections to saturate DB I/O.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L62-65)
```java
        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L76-81)
```java
    private long convertTimestamp(Timestamp timestamp) {
        if (timestamp.getSeconds() >= 9223372035L) {
            return Long.MAX_VALUE;
        }
        return DomainUtils.timestampInNanosMax(timestamp);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L28-31)
```java
    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L38-46)
```java
        Predicate predicate = cb.and(
                cb.equal(root.get(TOPIC_ID), filter.getTopicId()),
                cb.greaterThanOrEqualTo(root.get(CONSENSUS_TIMESTAMP), filter.getStartTime()));

        if (filter.getEndTime() != null) {
            predicate = cb.and(predicate, cb.lessThan(root.get(CONSENSUS_TIMESTAMP), filter.getEndTime()));
        }

        query = query.select(root).where(predicate).orderBy(cb.asc(root.get(CONSENSUS_TIMESTAMP)));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-59)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L27-35)
```java
    @Bean
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```
