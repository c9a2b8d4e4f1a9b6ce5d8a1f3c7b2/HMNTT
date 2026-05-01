### Title
Unbounded Concurrent gRPC Subscriptions with `startTime=0` Enable Database I/O Exhaustion (DoS)

### Summary
An unauthenticated external user can open an unlimited number of gRPC connections, each with up to 5 concurrent `subscribeTopic` calls using `startTime=0` and no `limit` against a topic with a large historical message backlog. Each subscription drives `PollingTopicMessageRetriever.poll()` to issue a 1,000-row database query every 2 seconds for up to 60 seconds before timing out. Because there is no global concurrent-subscriber cap and no per-IP rate limit on the gRPC service, many attackers (or one attacker with many connections) can sustain aggregate database I/O that exhausts the mirror node's database bandwidth and causes service unavailability.

### Finding Description

**Exact code path and root cause**

`TopicMessageServiceImpl.subscribeTopic()` calls the retriever in throttled mode:

```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
``` [1](#0-0) 

Inside `PollingTopicMessageRetriever.retrieve()`, throttled mode sets `numRepeats = Long.MAX_VALUE` and applies only a 60-second wall-clock timeout: [2](#0-1) 

Each repeat calls `poll()`, which unconditionally issues a DB query for `maxPageSize` (default 1,000) rows: [3](#0-2) 

The completion check `isComplete()` in throttled mode returns `true` only when the last page returned **fewer** rows than `maxPageSize`, or when a `limit` is hit: [4](#0-3) 

With billions of historical messages and no `limit` set, every page returns exactly 1,000 rows, so `isComplete()` is always `false`. The retriever polls every 2 seconds (`pollingFrequency` default) until the 60-second timeout fires — approximately 30 queries × 1,000 rows per subscriber lifetime. [5](#0-4) 

**Why input validation does not prevent this**

`TopicMessageFilter` accepts `startTime=0` as valid (`@Min(0)` and `startTime <= DomainUtils.now()`): [6](#0-5) 

**Why connection-level limits are insufficient**

`NettyProperties` caps concurrent calls *per connection* at 5, but places no limit on the number of connections: [7](#0-6) 

`GrpcConfiguration` only configures `maxConcurrentCallsPerConnection`; there is no `maxConnections` or global subscriber ceiling: [8](#0-7) 

`subscriberCount` in `TopicMessageServiceImpl` is a Micrometer gauge only — it is never checked against a maximum: [9](#0-8) 

Unlike the web3 module (which uses bucket4j rate limiting), the gRPC service has no equivalent throttle: [10](#0-9) 

### Impact Explanation

With N connections × 5 calls each, an attacker sustains N×5 concurrent subscribers. At the default 2-second polling interval and 1,000-row page size:

- **500 connections → 2,500 concurrent subscribers → 1,250,000 rows/second** read from the database continuously.

After each 60-second timeout the attacker reconnects, keeping the load perpetual. This exhausts database I/O bandwidth and connection pool resources, causing the mirror node gRPC service to become unavailable for all legitimate users. The mirror node is a read-only service and does not affect Hedera consensus, but its unavailability breaks all downstream applications relying on HCS topic subscriptions.

### Likelihood Explanation

- No authentication is required to open a gRPC subscription.
- `startTime=0` is explicitly accepted by the filter validator.
- Opening hundreds of TCP connections is trivial from a single host or a small botnet.
- The attack is fully repeatable: after each 60-second timeout the attacker simply reconnects.
- No special knowledge of the system internals is needed beyond the public gRPC API.

### Recommendation

1. **Enforce a global concurrent-subscriber limit**: Check `subscriberCount` against a configurable maximum in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` when exceeded.
2. **Add per-IP connection rate limiting** at the Netty/gRPC layer (e.g., via `maxConnectionsPerIp` or an external proxy rule).
3. **Require a minimum `startTime`** or cap the historical look-back window (e.g., reject `startTime` older than a configurable threshold such as 7 days) to bound the number of pages any single subscription can generate.
4. **Apply bucket4j-style rate limiting to the gRPC service**, mirroring the existing `ThrottleConfiguration` in the web3 module.
5. **Lower the default `timeout`** or make it non-configurable to reduce per-subscriber DB exposure.

### Proof of Concept

**Preconditions:**
- A Hedera topic exists with ≥ 1,000,000 historical messages (e.g., a high-throughput topic running for months).
- The mirror node gRPC endpoint is publicly reachable.

**Steps:**

```python
import grpc, threading
from com.hedera.hashgraph.sdk.proto import consensus_service_pb2_grpc, mirror_network_service_pb2 as pb

def flood(i):
    channel = grpc.insecure_channel("mirror.mainnet.hedera.com:443")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = pb.ConsensusTopicQuery(
        topicID=<high_volume_topic>,
        consensusStartTime={"seconds": 0, "nanos": 0},  # startTime=0
        # no limit set
    )
    for _ in stub.subscribeTopic(req):
        pass  # consume rows, keep connection alive

threads = [threading.Thread(target=flood, args=(i,)) for i in range(500)]
for t in threads: t.start()
for t in threads: t.join()
```

**Expected result:** 500 concurrent connections × 5 gRPC calls each = 2,500 concurrent subscribers, each issuing a 1,000-row DB query every 2 seconds. Database I/O saturates within seconds; legitimate subscribers receive errors or extreme latency; the mirror node gRPC service becomes unavailable.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L65-79)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L121-129)
```java
        boolean isComplete() {
            boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();

            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
            }

            return limitHit;
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L22-28)
```java
    private int maxPageSize = 1000;

    @NotNull
    private Duration pollingFrequency = Duration.ofSeconds(2L);

    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-51)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();

    @Builder.Default
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);

    @NotNull
    private EntityId topicId;

    public boolean hasLimit() {
        return limit > 0;
    }

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
