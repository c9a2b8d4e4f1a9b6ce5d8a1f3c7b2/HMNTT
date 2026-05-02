### Title
Unauthenticated gRPC Stream Flood Causes Repeated Redis Subscribe/Unsubscribe Thrashing via Unguarded `unsubscribe()` on `.share()` Cancellation

### Summary
The `RedisTopicListener.subscribe()` method attaches `doOnCancel(() -> unsubscribe(topic))` to the upstream Flux before `.share()`. When the last subscriber of the shared Flux cancels, Reactor's `refCount` drops to zero, cancels the upstream once, and fires `unsubscribe(topic)` — which unconditionally removes the topic from `topicMessages`. Because the gRPC `subscribeTopic` endpoint requires no authentication and has no per-client connection limit, an unprivileged attacker can repeatedly open and simultaneously cancel streams to the same topic, forcing continuous Redis subscribe/unsubscribe cycles and causing message loss for all legitimate subscribers during each resubscription window.

### Finding Description

**Exact code path:**

`getSharedListener` uses `ConcurrentHashMap.computeIfAbsent` to return (or create) a single shared Flux per topic: [1](#0-0) 

`subscribe()` builds the upstream Flux, places `doOnCancel` on it, then calls `.share()`: [2](#0-1) 

`unsubscribe()` unconditionally removes the topic from the map with no guard, debounce, or rate limit: [3](#0-2) 

The gRPC controller has no authentication, no per-IP connection limit, and no stream-count cap: [4](#0-3) 

**Root cause and failed assumption:**

The design assumes that `.share()` acts as a stable long-lived multicast: many subscribers share one Redis subscription, and `unsubscribe` is only called when the service legitimately shuts down. The failed assumption is that the refCount will never reach zero under adversarial conditions. In reality, `.share()` is `publish().refCount()`: when refCount hits zero (all subscribers cancel), it cancels the upstream and fires `doOnCancel` — removing the entry from `topicMessages`. The next subscriber then calls `computeIfAbsent`, finds the map empty, and creates a brand-new Redis subscription. There is no cooldown, no minimum-subscriber guard, and no re-use of the existing (now-cancelled) Flux.

**Exploit flow:**

1. Attacker opens N concurrent gRPC streams to topic T (no credentials needed, plaintext gRPC on port 5600 per docs).
2. All N streams subscribe to the same shared Flux returned by `computeIfAbsent`.
3. Attacker simultaneously cancels all N streams; `ServerCallStreamObserver.setOnCancelHandler(disposable::dispose)` disposes each subscription.
4. `.share()` sees refCount → 0, cancels the upstream, fires `doOnCancel` **once** → `unsubscribe(topic)` removes the entry from `topicMessages`.
5. Any new subscriber (including legitimate ones) triggers `computeIfAbsent` → `subscribe(topic)` → a fresh `ReactiveRedisMessageListenerContainer.receive(...)` call → new Redis SUBSCRIBE command.
6. Attacker immediately repeats from step 1. Each cycle is bounded only by network RTT and gRPC handshake time.

**Why existing checks are insufficient:**

- `ListenerProperties` exposes only `maxBufferSize`, `maxPageSize`, `interval`, and `prefetch` — no subscriber cap. [5](#0-4) 
- `TopicMessageServiceImpl` tracks `subscriberCount` as a metric gauge only — it is never used to reject connections. [6](#0-5) 
- No gRPC interceptor, no IP-based rate limiter, and no TLS/auth requirement is present in the grpc resource directory.

### Impact Explanation

Each attacker-driven cycle tears down the active Redis `SUBSCRIBE` and re-issues it. During the resubscription window (network RTT + Spring Data Redis reconnect), **all legitimate subscribers to that topic receive no messages** — a targeted, topic-specific message-loss DoS. With a high-frequency attack loop, the window is nearly continuous. Additionally, each cycle consumes a Redis connection slot and generates log noise, degrading overall server throughput. Severity: **High** (availability impact on the consensus message stream, which is the primary function of the mirror node gRPC API).

### Likelihood Explanation

The attack requires only a gRPC client (e.g., `grpcurl`, the Hedera SDK, or raw HTTP/2 frames) and knowledge of any valid topic ID. No credentials, no special network position, and no prior access are needed. The endpoint is documented as public. The attack is trivially scriptable, repeatable indefinitely, and requires no sustained bandwidth — only rapid connection open/close cycles. Likelihood: **High**.

### Recommendation

1. **Guard `unsubscribe` with a subscriber-count check**: Before removing from `topicMessages`, verify that the `.share()` Flux truly has zero downstream subscribers (e.g., use `publish().autoConnect(1, disposable -> ...)` with an explicit ref-counted wrapper that only removes when count is confirmed zero after a short debounce).
2. **Debounce resubscription**: Introduce a minimum hold time (e.g., equal to `listenerProperties.getInterval()`) before allowing a new `subscribe(topic)` call for the same topic key.
3. **Limit concurrent streams per topic or per client IP**: Add a gRPC `ServerInterceptor` that rejects `subscribeTopic` calls beyond a configurable per-IP or global-per-topic threshold.
4. **Use `autoConnect` instead of `refCount`**: Replace `.share()` with `.publish().autoConnect(1)` so the upstream is never cancelled when subscribers drop, eliminating the `doOnCancel` teardown path entirely for the live-listener use case.

### Proof of Concept

```bash
# Step 1: Open 500 concurrent streams to topic 0.0.41110, hold for 2 seconds, then cancel all
for i in $(seq 1 500); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 41110}}' \
    localhost:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
sleep 2
# Step 2: Kill all background grpcurl processes simultaneously
kill $(jobs -p)

# Step 3: Observe server logs: "Unsubscribing from topic.41110" followed immediately by
# "Creating shared subscription to topic.41110" — one full Redis UNSUBSCRIBE/SUBSCRIBE cycle.

# Step 4: Repeat the loop in a tight bash while-loop to sustain the thrash:
while true; do
  for i in $(seq 1 500); do
    grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}}' \
      localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
  sleep 1
  kill $(jobs -p)
  sleep 0.1
done
# Legitimate subscribers will observe continuous message gaps during each resubscription window.
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-53)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L17-43)
```java
public class ListenerProperties {

    private boolean enabled = true;

    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;

    @Min(32)
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);

    @Min(4)
    @Max(256)
    private int prefetch = 48;

    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
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
