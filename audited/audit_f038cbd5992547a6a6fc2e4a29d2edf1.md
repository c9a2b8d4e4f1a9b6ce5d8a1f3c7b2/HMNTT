### Title
Unbounded gRPC Subscriber Connections Enable File-Descriptor Exhaustion DoS

### Summary
`TopicMessageServiceImpl.subscribeTopic()` tracks active subscribers only via a Micrometer `Gauge` metric (`subscriberCount`) with no enforcement cap. Any unauthenticated caller can open an unlimited number of persistent gRPC streaming connections, each consuming an OS file descriptor, until the process FD limit is exhausted and the gRPC server can no longer accept new connections.

### Finding Description

**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`:

- Lines 48–55: `subscriberCount` is declared as a plain `AtomicLong` and registered only as a `Gauge` (observability only, zero enforcement). [1](#0-0) 

- Lines 87–91: `subscribeTopic()` increments `subscriberCount` via `doOnSubscribe` and decrements via `doFinally`. There is no guard that checks the current count against any maximum before accepting the subscription. [2](#0-1) 

- Lines 123–125: A subscription with no `endTime` returns `Flux.never()` from `pastEndTime()`, meaning the stream never self-terminates. [3](#0-2) 

**Root cause:** The only gate before a subscription is accepted is `topicExists()` (a DB lookup). No authentication interceptors, no per-IP rate limit, no global subscriber cap, and no gRPC-server-level `maxInboundConcurrentCallsPerConnection` configuration were found anywhere in the `grpc/` module. [4](#0-3) 

**Failed assumption:** The design assumes that `subscriberCount` being observable is sufficient; it is not — the value is never read back to gate new subscriptions.

### Impact Explanation

Each accepted gRPC streaming call holds at minimum one TCP socket (one OS file descriptor) for the lifetime of the stream. With no cap, an attacker can exhaust the process's FD limit (typically 1 024–65 536 on Linux). Once exhausted, the Netty event loop cannot `accept()` new TCP connections, causing `EMFILE`/`ENFILE` errors. All legitimate subscribers and any other gRPC clients are denied service. Because the streams are infinite (no `endTime`), the attacker does not need to continuously reconnect — a single burst of connections is sufficient to maintain the DoS.

### Likelihood Explanation

No authentication is required. The attacker needs only a gRPC client (e.g., `grpcurl`, a trivial Go/Python script) and knowledge of any valid topic ID (or `checkTopicExists=false` mode). The attack is repeatable, scriptable, and requires no special privileges or insider knowledge. A single commodity machine can open tens of thousands of TCP connections.

### Recommendation

1. **Enforce a hard cap** inside `subscribeTopic()` before the subscription is accepted:
   ```java
   if (subscriberCount.get() >= grpcProperties.getMaxSubscribers()) {
       return Flux.error(new StatusRuntimeException(Status.RESOURCE_EXHAUSTED));
   }
   ```
   Expose `maxSubscribers` as a configurable property in `GrpcProperties`.

2. **Configure gRPC-server-level limits** (e.g., `grpc.server.max-inbound-concurrent-calls-per-connection` or Netty `maxConcurrentCallsPerConnection`) to bound connections at the transport layer.

3. **Add per-IP connection rate limiting** via a gRPC `ServerInterceptor` to prevent rapid reconnection after the cap is hit.

4. **Set a maximum stream lifetime** (idle timeout / `maxConnectionAge`) so abandoned streams are reaped automatically.

### Proof of Concept

```bash
# Requires: grpcurl, a running mirror-node gRPC endpoint, any valid topicId

for i in $(seq 1 10000); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 1}}' \
    <host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    > /dev/null 2>&1 &
done

# Each background process holds an open gRPC stream (no endTime → infinite).
# After ~(ulimit -n) connections the server returns UNAVAILABLE to all new callers.
# Verify: watch -n1 'ss -tnp | grep 5600 | wc -l'
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-92)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });

        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }

        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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
