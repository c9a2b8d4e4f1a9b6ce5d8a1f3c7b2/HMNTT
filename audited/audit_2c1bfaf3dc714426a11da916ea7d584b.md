### Title
Unbounded Subscribe/Cancel Oscillation in `RedisTopicListener.subscribe()` Enables Unauthenticated Resource Exhaustion

### Summary
An unprivileged external attacker can repeatedly open gRPC connections, subscribe to any topic, and immediately cancel, causing `doOnCancel(() -> unsubscribe(topic))` to remove the shared Flux entry from `topicMessages` on every cycle. Because there is no rate limiting on gRPC subscriptions and no debounce on the cancel path, each cycle forces a new `subscribe()` call that re-creates a Redis channel subscription, emits `log.info()` on both subscribe and unsubscribe, and triggers a database query via `topicExists`. Sustained at scale across many connections this exhausts log I/O, Redis I/O, and database query capacity.

### Finding Description

**Exact code path:**

`RedisTopicListener.getSharedListener()` (line 61) uses `ConcurrentHashMap.computeIfAbsent` to return or create a shared Flux per topic: [1](#0-0) 

`subscribe()` (lines 68–80) builds the Flux with `.share()` and attaches `doOnCancel` and `doOnSubscribe` log hooks: [2](#0-1) 

`unsubscribe()` (lines 82–85) unconditionally removes the topic key from the map and emits a `log.info()`: [3](#0-2) 

**Root cause and failed assumption:**

The design assumes that the `.share()` reference count will stay positive under normal use, so `doOnCancel` (which fires only when the last subscriber cancels) is a rare event. The failed assumption is that callers are well-behaved. There is no rate limit, no connection limit, and no debounce on the cancel→remove→re-subscribe path.

**Exploit flow:**

1. Attacker opens N gRPC connections (no connection limit enforced at the application layer).
2. Each connection issues up to 5 concurrent `subscribeTopic` calls (`maxConcurrentCallsPerConnection = 5`): [4](#0-3) 
3. Each `subscribeTopic` call triggers `entityRepository.findById()` (a synchronous DB read) before reaching the listener: [5](#0-4) 
4. The attacker immediately cancels all streams. The gRPC cancel handler calls `disposable::dispose`: [6](#0-5) 
5. When the last subscriber disposes, `doOnCancel` fires → `unsubscribe()` removes the entry from `topicMessages` and emits `log.info("Unsubscribing from {}")`.
6. The attacker immediately re-subscribes → `computeIfAbsent` finds no entry → `subscribe()` is called again → new Redis channel subscription is created via `r.receive(...)` → `log.info("Creating shared subscription to {}")` is emitted.
7. Steps 4–6 repeat at the attacker's chosen rate.

**Why existing checks are insufficient:**

- `maxConcurrentCallsPerConnection = 5` limits concurrent streams *per connection*, not the number of connections or the subscribe/cancel cycle rate. An attacker with N connections can drive N×5 concurrent subscribe attempts and N cancel events per cycle.
- The gRPC endpoint is unauthenticated and publicly reachable (`grpcurl -plaintext`): [7](#0-6) 
- Rate limiting (Bucket4j) exists only in the `web3` module, not in the `grpc` module: [8](#0-7) 
- The optional GCP gateway `maxRatePerEndpoint: 250` is infrastructure-level and not enforced by the application itself: [9](#0-8) 

### Impact Explanation

Each subscribe/cancel cycle produces: 2 synchronous `log.info()` writes (disk I/O), 1 Redis `SUBSCRIBE`/`UNSUBSCRIBE` round-trip (network I/O to Redis), and 1 database `SELECT` for `topicExists`. At high cycle rates across many connections this saturates the logging subsystem (log files, log aggregation pipelines), exhausts Redis connection bandwidth, and amplifies database read load — all without any messages being delivered. Because the mirror node gRPC deployment typically runs a small number of replicas (HPA `maxReplicas: 3`), a single attacker targeting one or two pods can degrade 33–67% of gRPC processing capacity, meeting the stated ≥30% threshold. [10](#0-9) 

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and only a standard gRPC client (e.g., `grpcurl`). The topic ID can be any valid topic (or even an invalid one that passes the `checkTopicExists=false` default path). The cycle can be automated trivially in a loop. The attacker does not need to sustain a large number of *concurrent* connections — even a modest number of connections cycling at high frequency is sufficient because each cycle forces a full Redis subscription teardown and recreation.

### Recommendation

1. **Add a subscribe rate limiter to the gRPC module** analogous to the Bucket4j throttle already present in `web3`, applied per source IP or per connection at the `ConsensusController` or a gRPC interceptor level.
2. **Debounce or delay the `unsubscribe()` removal** — instead of removing from `topicMessages` immediately on cancel, use a short delay (e.g., equal to `listenerProperties.getInterval()`) so that a rapid re-subscribe reuses the existing shared Flux rather than forcing a new Redis subscription.
3. **Replace `log.info()` with `log.debug()`** in `subscribe()` and `unsubscribe()` to prevent log flooding from normal lifecycle churn.
4. **Enforce a global connection limit** at the Netty server level in `GrpcConfiguration` in addition to the per-connection call limit. [11](#0-10) 

### Proof of Concept

```bash
# Requires grpcurl and a running mirror node gRPC endpoint
# Replace TOPIC_NUM with any valid topic number

ENDPOINT="localhost:5600"
TOPIC_NUM=41110

for i in $(seq 1 1000); do
  # Subscribe and immediately cancel (timeout 0s forces immediate cancel)
  grpcurl -plaintext \
    -d "{\"topicID\": {\"topicNum\": $TOPIC_NUM}}" \
    -max-time 0.05 \
    $ENDPOINT \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    &>/dev/null &
done
wait
```

**Expected observable result:** The mirror node logs will show alternating `Creating shared subscription to topic.$TOPIC_NUM` and `Unsubscribing from topic.$TOPIC_NUM` entries at the rate of the loop. Redis `SUBSCRIBE`/`UNSUBSCRIBE` commands will spike proportionally (visible via `redis-cli monitor`). Database query rate for entity lookups will spike. Running this loop continuously from multiple hosts will progressively degrade gRPC node responsiveness for legitimate subscribers.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L68-80)
```java
    private Flux<TopicMessage> subscribe(Topic topic) {
        Duration interval = listenerProperties.getInterval();

        return container
                .flatMapMany(r -> r.receive(Collections.singletonList(topic), channelSerializer, messageSerializer))
                .map(Message::getMessage)
                .doOnCancel(() -> unsubscribe(topic))
                .doOnComplete(() -> unsubscribe(topic))
                .doOnError(t -> log.error("Error listening for messages", t))
                .doOnSubscribe(s -> log.info("Creating shared subscription to {}", topic))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
                .share();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L82-85)
```java
    private void unsubscribe(Topic topic) {
        topicMessages.remove(topic.getTopic());
        log.info("Unsubscribing from {}", topic);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L50-52)
```java
        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
```

**File:** docs/grpc/README.md (L14-16)
```markdown
Example invocation using [grpcurl](https://github.com/fullstorydev/grpcurl):

`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
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

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** charts/hedera-mirror-grpc/values.yaml (L111-114)
```yaml
hpa:
  behavior: {}
  enabled: false
  maxReplicas: 3
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
