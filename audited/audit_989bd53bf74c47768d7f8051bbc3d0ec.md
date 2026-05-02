### Title
Unbounded Per-Topic Subscription Flood Enables DoS via Resource Exhaustion in `subscribeTopic()`

### Summary
`TopicMessageServiceImpl.subscribeTopic()` accepts an unlimited number of concurrent subscriptions to any topic from any unauthenticated caller. The only global counter, `subscriberCount`, is used exclusively as a metrics gauge and is never enforced as a cap. An unprivileged attacker can open thousands of subscriptions to a single topic, exhausting thread pool, memory (per-subscriber backpressure buffers), and database connections, starving legitimate subscribers of messages.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `topicListener.listen()` (via `incomingMessages()`)

In `TopicMessageServiceImpl.java` lines 48–56, `subscriberCount` is declared and registered as a Micrometer `Gauge` only:

```java
private final AtomicLong subscriberCount = new AtomicLong(0L);
// ...
Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
    .register(meterRegistry);
```

In `subscribeTopic()` lines 87–91, it is incremented/decremented purely for observability — never checked against any maximum:

```java
return topicExists(filter)
    .thenMany(flux.doOnNext(topicContext::onNext)
        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
        .doFinally(s -> subscriberCount.decrementAndGet())
        ...);
```

`topicExists()` (lines 94–106) only validates that the entity exists and has type `TOPIC`. No authentication, no per-topic subscriber cap, no per-caller rate limit.

The only connection-level guard is `maxConcurrentCallsPerConnection = 5` in `NettyProperties.java` line 14, enforced in `GrpcConfiguration.java` line 33. This is trivially bypassed by opening multiple TCP connections.

**Per listener type, the resource impact differs:**

- **`POLL` mode (`PollingTopicListener`)**: Each subscription creates an independent `Flux.defer(() -> poll(context)).repeatWhen(...)` polling loop on `Schedulers.boundedElastic()`. N subscriptions = N independent DB polling loops, directly exhausting the DB connection pool and bounded elastic thread pool.

- **`SHARED_POLL` / `REDIS` mode (`SharedTopicListener`)**: The shared Flux is one source, but `SharedTopicListener.listen()` (line 24) applies `onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)` **per subscriber**. With default `maxBufferSize = 16384` and a `TopicMessage` object size, thousands of subscribers each holding a 16384-element buffer causes heap exhaustion. Additionally, `publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch())` allocates a thread per active subscriber delivery, exhausting the bounded elastic scheduler.

### Impact Explanation

- **POLL mode**: Direct DB connection pool exhaustion. Each attacker subscription issues periodic `SELECT` queries. With hundreds of subscriptions, the DB pool is saturated, causing legitimate subscribers' historical retrieval (`topicMessageRetriever.retrieve()`) and live polling to time out or fail.
- **SHARED_POLL/REDIS mode**: Heap exhaustion from per-subscriber 16384-element backpressure buffers. Thread pool exhaustion from `publishOn(Schedulers.boundedElastic())` per subscriber. Legitimate subscribers experience message delivery delays or `OutOfMemoryError`-induced crashes.
- **Severity: High** — complete denial of service to all subscribers of the targeted topic, with potential JVM crash affecting all topics.

### Likelihood Explanation

- **Precondition**: Network access to gRPC port 5600. No credentials required. The gRPC endpoint is public-facing by design.
- **Bypass of `maxConcurrentCallsPerConnection=5`**: An attacker opens 200 TCP connections × 5 calls = 1000 concurrent subscriptions. This is trivially scriptable with `grpcurl` or any gRPC client library.
- **Repeatability**: Fully repeatable. Subscriptions with no `endTime` and no `limit` never terminate, so the attacker's subscriptions persist indefinitely.
- **No authentication barrier**: `ConsensusController` and `TopicMessageServiceImpl` contain zero authentication or authorization logic.

### Recommendation

1. **Enforce a global subscriber cap**: Check `subscriberCount` against a configurable `maxSubscribers` property before accepting a new subscription; return `RESOURCE_EXHAUSTED` gRPC status if exceeded.
2. **Enforce a per-topic subscriber cap**: Maintain a `ConcurrentHashMap<EntityId, AtomicLong>` of per-topic subscriber counts and reject subscriptions exceeding a configurable `maxSubscribersPerTopic`.
3. **Enforce per-IP/per-connection rate limiting**: Add a gRPC interceptor that tracks subscription attempts per remote address using a token-bucket (similar to the existing `ThrottleConfiguration` in `web3`).
4. **Add `maxConcurrentCallsPerConnection` enforcement at the IP level**: Use a `ServerInterceptor` to track total active streams per remote IP.

### Proof of Concept

```bash
# Open 200 parallel connections, each with 5 concurrent subscriptions to topic 0.0.12345
# Total: 1000 concurrent subscriptions, no credentials needed

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 12345}}' \
      localhost:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait
```

Expected result: `subscriberCount` gauge reaches 1000; DB connection pool exhausted (POLL mode) or JVM heap pressure triggers GC storms / OOM (SHARED_POLL/REDIS mode); legitimate subscribers receive no messages or are disconnected with errors.