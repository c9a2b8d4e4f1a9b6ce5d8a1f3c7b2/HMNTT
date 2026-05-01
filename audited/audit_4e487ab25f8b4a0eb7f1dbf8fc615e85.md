### Title
Unbounded Polling Loop via `PollingTopicListener.listen()` Enables DB Resource Exhaustion by Unprivileged Users

### Summary
When the gRPC listener is configured with `type=POLL`, any unauthenticated user can subscribe to a valid but message-less topic and cause `PollingTopicListener.listen()` to issue database queries indefinitely at the configured interval. There is no per-connection rate limit, no subscription cap, and no idle-connection termination in the gRPC module, so N concurrent attacker connections produce N×(1/interval) DB queries for the lifetime of each connection.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `topicExists()` (passes for any valid topic entity) → `incomingMessages()` → `topicListener.listen(newFilter)` → `PollingTopicListener.listen()`.

**Root cause — `PollingTopicListener.listen()` lines 38–43:**

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)   // ← effectively infinite
                .jitter(0.1)
                .withFixedDelay(interval)              // default 500 ms
                .withScheduler(scheduler))
``` [1](#0-0) 

Every iteration unconditionally calls `poll()`, which executes a DB query regardless of whether any results are returned:

```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
``` [2](#0-1) 

**Why the existing `topicExists()` check is insufficient:**

`topicExists()` only verifies that the entity exists in the DB and is of type `TOPIC`. It does not terminate or throttle the subscription if the topic is empty or idle. [3](#0-2) 

When `checkTopicExists=false` (a supported configuration), even non-existent topic IDs bypass this check entirely and the polling loop still runs: [4](#0-3) 

**No rate limiting on gRPC subscriptions:** The only throttle infrastructure in the codebase (`ThrottleConfiguration`, `ThrottleManagerImpl`) is scoped exclusively to the `web3` module for contract calls. There is no equivalent for the `grpc` module. [5](#0-4) 

**Polling interval floor:** The minimum configurable interval is 50 ms, meaning up to 20 DB queries per second per connection at the extreme. [6](#0-5) 

### Impact Explanation

Each open gRPC subscription in POLL mode consumes one `boundedElastic` scheduler thread and issues one DB query every `interval` milliseconds for the entire connection lifetime. With the default 500 ms interval, 1,000 concurrent attacker connections produce 2,000 DB queries per second of zero-result work. This degrades query latency for legitimate subscribers (the existing `GrpcQueryLatency` alert fires at >1 s average latency), can exhaust the HikariCP connection pool (the `GrpcHighDatabaseConnections` alert fires at >75% utilization), and starves the `boundedElastic` thread pool. The impact is service degradation or denial of service for all gRPC consumers without any economic cost to the attacker.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly documented and requires no authentication or API key. Any client with network access can open arbitrarily many concurrent gRPC streams. The only precondition is knowing one valid topic ID (trivially discoverable via the public REST API). The attack is fully repeatable, scriptable, and requires no special privileges. The POLL listener type is a documented, supported configuration option (`ListenerType.POLL`). [7](#0-6) 

### Recommendation

1. **Add a maximum concurrent subscriber limit** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold.
2. **Add per-IP or per-topic connection rate limiting** at the gRPC interceptor layer, analogous to the `ThrottleManagerImpl` in the `web3` module.
3. **Terminate idle polling subscriptions**: if no messages are received within a configurable idle timeout (e.g., `endTime` semantics or a configurable `maxIdleDuration`), complete the stream rather than polling indefinitely.
4. **Raise the minimum interval floor** or add a backoff when consecutive polls return zero results, to reduce DB pressure from idle subscriptions.

### Proof of Concept

**Preconditions:**
- Mirror node configured with `hiero.mirror.grpc.listener.type=POLL`
- At least one valid topic entity exists (e.g., topic `0.0.1000`) with no recent messages
- OR `hiero.mirror.grpc.checkTopicExists=false` (any topic ID works)

**Steps:**

```bash
# Open 500 concurrent gRPC subscriptions to an empty topic
for i in $(seq 1 500); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 1000}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
```

**Result:** Each connection triggers `PollingTopicListener.listen()` with `RepeatSpec.times(Long.MAX_VALUE)`. With the default 500 ms interval, 500 connections issue 1,000 empty `findByFilter` DB queries per second indefinitely. DB connection pool utilization climbs, query latency for legitimate subscribers increases, and the `GrpcQueryLatency` / `GrpcHighDatabaseConnections` alerts fire. All connections remain open until the attacker terminates them.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L61-61)
```java
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L28-30)
```java
    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L39-43)
```java
    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```
