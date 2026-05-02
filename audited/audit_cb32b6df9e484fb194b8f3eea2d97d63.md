### Title
Unbounded Redis Subscription Churn via Near-Future `endTime` in `RedisTopicListener`

### Summary
An unprivileged external user can open many concurrent gRPC `subscribeTopic` calls with a minimally valid `endTime` (just above `startTime`), causing each subscription to complete after one `endTimeInterval` (~30 seconds by default). Upon completion, `doOnCancel(() -> unsubscribe(topic))` fires on the shared Redis Flux, removing the topic from `topicMessages` and forcing a new Redis `SUBSCRIBE` command on the next request. With enough concurrent connections, an attacker can sustain continuous Redis subscription churn, degrading service for legitimate users.

### Finding Description

**Code path:**

`RedisTopicListener.getSharedListener()` keys the shared subscription map only on topic ID: [1](#0-0) 

`subscribe()` attaches `doOnCancel(() -> unsubscribe(topic))` and `doOnComplete(() -> unsubscribe(topic))` to the shared Flux: [2](#0-1) 

`unsubscribe()` removes the topic from the map unconditionally: [3](#0-2) 

**Completion trigger:**

`TopicContext.isComplete()` returns `true` when `Instant.ofEpochSecond(0, endTime).plus(endTimeInterval).isBefore(Instant.now())`: [4](#0-3) 

`pastEndTime()` polls every `endTimeInterval` (default 30 s) and completes when `isComplete()` is true: [5](#0-4) 

`takeUntilOther(pastEndTime(...))` then cancels the downstream, which propagates a cancel upstream through the `share()` operator, triggering `doOnCancel(() -> unsubscribe(topic))`.

**Root cause:** `incomingMessages()` only skips the Redis subscription when `isComplete()` is already true at call time (i.e., `endTime < startTime`): [6](#0-5) 

For a near-future `endTime` (e.g., `startTime + 1 ns`), `isComplete()` is false at subscription time, so `topicListener.listen()` is called and a Redis `SUBSCRIBE` is issued. After ~30 seconds the subscription completes, `unsubscribe()` removes the entry, and the cycle repeats.

**Validation check — `isValidEndTime()`** only requires `endTime > startTime`, with no minimum duration: [7](#0-6) 

No rate limiting exists on the gRPC subscription endpoint; the only per-connection concurrency cap is `maxConcurrentCallsPerConnection = 5`: [8](#0-7) 

There is no limit on the number of connections, so an attacker can open arbitrarily many.

### Impact Explanation
Each attacker-controlled subscription creates a real Redis `SUBSCRIBE` command via `ReactiveRedisMessageListenerContainer.receive()`. After ~30 seconds it is torn down and re-created. With N connections × 5 concurrent calls, each using a distinct topic ID, the attacker sustains N×5 Redis subscription create/destroy cycles every 30 seconds. This can exhaust Redis connection slots, saturate the listener container's thread pool, and cause legitimate subscribers to experience degraded or dropped service.

### Likelihood Explanation
No authentication is required to call `subscribeTopic`. The only constraint is that `endTime > startTime` and `startTime <= now`, both trivially satisfied. An attacker needs only a standard gRPC client and the ability to open many TCP connections. The attack is fully repeatable and automatable.

### Recommendation
1. **Enforce a minimum subscription duration**: Reject filters where `endTime - startTime < some_minimum` (e.g., 60 seconds) in `isValidEndTime()`.
2. **Rate-limit new subscriptions per IP/client**: Add a token-bucket or sliding-window rate limiter at the gRPC interceptor layer, similar to the `ThrottleConfiguration` used in the web3 module.
3. **Limit total connections per IP**: Configure Netty's `maxConnectionsPerIp` or use an upstream proxy/load-balancer with connection limits.
4. **Decouple `unsubscribe` from per-subscriber cancel**: Instead of removing the shared entry on every cancel, use reference counting with a minimum TTL before actually issuing Redis `UNSUBSCRIBE`.

### Proof of Concept
```python
import grpc, threading, time
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc
from google.protobuf.timestamp_pb2 import Timestamp

TARGET = "mirror-node:5600"
TOPIC_ID = ...  # any valid topic ID
NOW_S = int(time.time())

def attack_subscription(i):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_pb2.ConsensusTopicQuery(
        topicID=...,
        consensusStartTime=Timestamp(seconds=0, nanos=0),
        # endTime = now + 1 nanosecond: passes isValidEndTime, triggers ~30s cycle
        consensusEndTime=Timestamp(seconds=NOW_S, nanos=1),
    )
    try:
        for _ in stub.subscribeTopic(query):
            pass
    except Exception:
        pass
    channel.close()

# Open 200 threads × 5 concurrent calls = 1000 Redis subscriptions cycling every 30s
while True:
    threads = [threading.Thread(target=attack_subscription, args=(i,)) for i in range(200)]
    for t in threads: t.start()
    for t in threads: t.join()
```

Each thread completes after ~30 seconds (one `endTimeInterval`), triggering `unsubscribe()` on the shared Redis Flux for each distinct topic ID used, then immediately re-subscribing. Sustained over time this causes continuous Redis subscription churn with no authentication required.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L108-121)
```java
    private Flux<TopicMessage> incomingMessages(TopicContext topicContext) {
        if (topicContext.isComplete()) {
            return Flux.empty();
        }

        TopicMessageFilter filter = topicContext.getFilter();
        TopicMessage last = topicContext.getLast();
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();

        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-215)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }

            if (filter.getEndTime() < startTime) {
                return true;
            }

            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-46)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-34)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```
