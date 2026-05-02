### Title
Unauthenticated Redis PUBLISH Injection Allows Falsified `consensusTimestamp` Delivery to gRPC Subscribers

### Summary
The `docker-compose.yml` ships Redis with port `6379` bound to all interfaces and no password, allowing any network-reachable attacker to publish a crafted `TopicMessage` directly to a `topic.<id>` channel. `RedisTopicListener.subscribe()` deserializes and forwards the message to gRPC clients with zero validation of the `consensusTimestamp` field against the actual consensus ledger, causing subscribers to receive a message whose consensus time is entirely attacker-controlled.

### Finding Description

**Unauthenticated Redis exposure:**
`docker-compose.yml` lines 95–102 deploy Redis as `redis:6-alpine` with `ports: - 6379:6379` and no `requirepass`, `bind 127.0.0.1`, or any ACL configuration. Any host-reachable client can connect and issue `PUBLISH` without credentials. [1](#0-0) 

**No-op `subscribe()` pipeline:**
`RedisTopicListener.subscribe()` (lines 68–80) subscribes to the channel and maps each received payload directly to a `TopicMessage` via `Message::getMessage`. There is no step that cross-checks `consensusTimestamp` against the database, the importer's last-known timestamp, or any other authoritative source. [2](#0-1) 

**Injected message passes through `missingMessages` unchecked:**
In `TopicMessageServiceImpl.incomingMessages()` (line 120), each Redis-sourced message is passed to `missingMessages(topicContext, t)`. When the injected message carries a sequence number equal to `last + 1` (i.e., `topicContext.isNext(current)` is `true`), `missingMessages` returns `Flux.just(current)` at line 153 — the message is forwarded as-is with no DB lookup. [3](#0-2) 

**Only sequence-number ordering is checked, not timestamp authenticity:**
The sole filter applied to live messages (line 74–77) rejects messages whose `sequenceNumber` is not greater than the last seen one. The `consensusTimestamp` field is never validated against the ledger. [4](#0-3) 

**Falsified timestamp propagated verbatim to gRPC response:**
`ConsensusController.toResponse()` (line 86) calls `t.getConsensusTimestamp()` directly to populate the `consensusTimestamp` field of the `ConsensusTopicResponse` proto sent to subscribers. [5](#0-4) 

**`TopicMessage.consensusTimestamp` is a plain mutable `long`:**
The domain object carries no integrity protection; any value serialized into the MessagePack payload is accepted. [6](#0-5) 

### Impact Explanation
A gRPC subscriber calling `subscribeTopic` receives `ConsensusTopicResponse` messages whose `consensusTimestamp` is presented as authoritative Hashgraph consensus history. An attacker who injects a message with a past or future timestamp causes the subscriber to record a false ordering of events on the ledger — directly rewriting perceived Hashgraph history for that topic. Applications that use the gRPC stream to drive business logic (e.g., DeFi settlement, audit trails, cross-chain bridges) can be deceived into accepting fraudulent state transitions. Severity is **Critical** for deployments where the gRPC stream is treated as a trusted source of truth.

### Likelihood Explanation
In the docker-compose deployment (the reference configuration shipped in the repository), Redis is reachable on port 6379 from any host with network access and requires no credentials. The attacker only needs to: (1) know the target topic ID (public information), (2) serialize a `TopicMessage` in MessagePack format (the serializer is `Jackson2JsonRedisSerializer` with `MessagePackFactory`, fully documented in `RedisConfiguration`), and (3) issue a single `PUBLISH topic.<id> <payload>` command. No account, API key, or privileged access is required. The attack is repeatable and scriptable. [7](#0-6) 

### Recommendation
1. **Enforce Redis authentication unconditionally.** The docker-compose configuration must set `requirepass` and pass the password via `SPRING_DATA_REDIS_PASSWORD`. The current Helm chart generates a random password but the docker-compose does not.
2. **Validate `consensusTimestamp` on ingestion.** In `RedisTopicListener.subscribe()` or `TopicMessageServiceImpl.incomingMessages()`, cross-check the received `consensusTimestamp` against the database (e.g., verify it exists in `topic_message` with the matching `sequenceNumber`) before forwarding to subscribers.
3. **Bind Redis to loopback only** in all non-production configurations (`bind 127.0.0.1`).
4. **Apply Redis ACLs** to restrict `PUBLISH` to the importer service account only.

### Proof of Concept

```bash
# 1. Start the docker-compose stack (Redis exposed on 0.0.0.0:6379, no auth)
docker compose up -d

# 2. Install redis-cli and msgpack serializer (Python example)
pip install redis msgpack

# 3. Craft and publish a TopicMessage with falsified consensusTimestamp
python3 - <<'EOF'
import redis
import msgpack

r = redis.Redis(host='<mirror-node-host>', port=6379)

# Serialize a TopicMessage in MessagePack matching Jackson2JsonRedisSerializer layout
# @type discriminator required by @JsonTypeInfo(use=Id.NAME) / @JsonTypeName("TopicMessage")
payload = msgpack.packb({
    "@type": "TopicMessage",
    "consensusTimestamp": 1,          # falsified: epoch nanosecond 1 (year 1970)
    "sequenceNumber": <next_seq>,     # must be last_seen + 1 to pass sequence filter
    "topicId": <encoded_topic_id>,
    "message": b"fake",
    "runningHash": b"\x00" * 48,
    "runningHashVersion": 3,
}, use_bin_type=True)

r.publish("topic.<topic_num>", payload)
print("Injected message published")
EOF

# 4. Any active gRPC subscriber on that topic receives a ConsensusTopicResponse
#    with consensusTimestamp = 1 nanosecond (1970-01-01T00:00:00.000000001Z)
#    — a timestamp that predates the Hashgraph network's existence.
```

### Citations

**File:** docker-compose.yml (L95-102)
```yaml
  redis:
    image: redis:6-alpine
    ports:
      - 6379:6379
    restart: unless-stopped
    stop_grace_period: 2m
    stop_signal: SIGTERM
    tty: true
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L74-77)
```java
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L138-154)
```java
    private Flux<TopicMessage> missingMessages(TopicContext topicContext, @Nullable TopicMessage current) {
        final var last = topicContext.getLast();

        // Safety check triggered
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
        }

        if (last == null || topicContext.isNext(current)) {
            return Flux.just(current);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L84-92)
```java
    private ConsensusTopicResponse toResponse(TopicMessage t) {
        final var consensusTopicResponseBuilder = ConsensusTopicResponse.newBuilder()
                .setConsensusTimestamp(ProtoUtil.toTimestamp(t.getConsensusTimestamp()))
                .setMessage(ProtoUtil.toByteString(t.getMessage()))
                .setRunningHash(ProtoUtil.toByteString(t.getRunningHash()))
                .setRunningHashVersion(
                        Objects.requireNonNullElse(t.getRunningHashVersion(), DEFAULT_RUNNING_HASH_VERSION))
                .setSequenceNumber(t.getSequenceNumber());

```

**File:** common/src/main/java/org/hiero/mirror/common/domain/topic/TopicMessage.java (L38-39)
```java
    @Id
    private long consensusTimestamp;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/RedisConfiguration.java (L34-42)
```java
    RedisSerializer<TopicMessage> redisSerializer() {
        var module = new SimpleModule();
        module.addDeserializer(EntityId.class, EntityIdDeserializer.INSTANCE);
        module.addSerializer(EntityIdSerializer.INSTANCE);

        var objectMapper = new ObjectMapper(new MessagePackFactory());
        objectMapper.registerModule(module);
        return new Jackson2JsonRedisSerializer<>(objectMapper, TopicMessage.class);
    }
```
