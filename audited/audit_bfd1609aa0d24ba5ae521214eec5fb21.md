### Title
Unauthenticated Thundering Herd via Synchronized Safety-Check DB Queries in `subscribeTopic()`

### Summary
Every call to `subscribeTopic()` unconditionally schedules a `Mono.delay(Duration.ofSeconds(1L))` safety-check that fires a database retrieval query for all live (no `endTime`) subscriptions. Because there is no global subscription limit, no per-IP connection cap, and no rate limiting on the gRPC subscription endpoint, an unauthenticated attacker can open thousands of subscriptions simultaneously, causing all their safety-check DB queries to fire in a synchronized burst exactly one second later, overwhelming the database connection pool.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 67–70:
```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
```

**Root cause — three compounding failures:**

1. **Safety check always fires for live subscriptions.** `isComplete()` (lines 203–215) returns `false` unconditionally when `filter.getEndTime() == null`. A live subscription never sets `endTime`, so `!topicContext.isComplete()` is always `true`, and the safety check always passes the filter and calls `missingMessages(topicContext, null)`.

2. **`missingMessages(null)` issues a real DB query.** When `current == null` (safety-check path, lines 142–150), it calls `topicMessageRetriever.retrieve(gapFilter, false)` — the *unthrottled* retriever path. Per `RetrieverProperties`, unthrottled mode uses `maxPolls=12`, `pollingFrequency=20ms`, `maxPageSize=5000`, meaning each safety-check trigger can issue up to 13 sequential DB queries over ~240 ms.

3. **No global subscription limit or gRPC rate limiting.** The only per-connection guard is `maxConcurrentCallsPerConnection = 5` (`NettyProperties`, `GrpcConfiguration` line 33). This limits calls *per connection*, not total connections or total subscriptions. The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module and is entirely absent from the `grpc` module. `subscriberCount` is a metrics gauge only — it enforces nothing.

**Exploit flow:**

An attacker opens `C` gRPC connections simultaneously, each with 5 concurrent `subscribeTopic` calls (the per-connection maximum), for `5C` total live subscriptions. All subscriptions are created within the same sub-second window. After exactly 1 second, all `5C` safety-check `Mono.delay` timers expire simultaneously. Each fires `retrieve(gapFilter, false)` (unthrottled), which can issue up to 13 DB queries. Total burst: up to `5C × 13` DB queries in ~240 ms.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` is per-connection; with `C` connections the total is `5C` with no ceiling.
- `Schedulers.boundedElastic()` limits threads (default: `10 × CPU cores`) but queues up to 100,000 tasks — it does not drop or reject work.
- No IP-level connection throttle is configured in `NettyServerBuilder`.
- No authentication or authorization is required to call `subscribeTopic`.

### Impact Explanation

A sustained burst of `5C` simultaneous DB queries exhausts the JDBC/R2DBC connection pool. Pool exhaustion causes all other gRPC and REST queries to queue or time out, degrading or halting the mirror node's ability to serve any data. Because the mirror node is the sole source of HCS topic message history for downstream consumers, a crash here prevents clients from confirming new transactions, matching the stated critical severity (total network shutdown from the mirror node's perspective).

### Likelihood Explanation

The attack requires no credentials, no special knowledge beyond the public gRPC port (default 5600), and no protocol-level tricks — only the ability to open many TCP connections and send valid `subscribeTopic` gRPC requests. Standard gRPC client libraries make this trivial. The attack is repeatable: after the burst subsides, the attacker simply reconnects and repeats. The 1-second fixed delay makes the synchronization deterministic and reliable.

### Recommendation

1. **Add a global concurrent-subscription cap** enforced atomically against `subscriberCount` before accepting a new subscription; return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP connection rate limiting** at the `NettyServerBuilder` level (e.g., via a Netty `ChannelHandler` or an external proxy).
3. **Jitter the safety-check delay** (e.g., `Duration.ofSeconds(1L).plus(random 0–500 ms)`) so subscriptions opened simultaneously do not fire simultaneously.
4. **Gate the safety-check on whether historical retrieval has actually completed** rather than firing unconditionally for all live subscriptions.
5. **Apply the existing `ThrottleManager` pattern** (already used in `web3`) to the gRPC subscription endpoint.

### Proof of Concept

```python
import grpc, threading, time
# Assumes proto stubs for the mirror node consensus service
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

TARGET = "mirror-node-host:5600"
CONNECTIONS = 200   # 200 connections × 5 calls = 1000 simultaneous subscriptions

def subscribe(stub):
    req = consensus_service_pb2.ConsensusTopicQuery(
        topicID=...,   # any valid topic ID
        # no consensusEndTime → live subscription, isComplete() always false
    )
    for _ in stub.subscribeTopic(req):
        pass  # drain silently

channels = [grpc.insecure_channel(TARGET) for _ in range(CONNECTIONS)]
stubs   = [consensus_service_pb2_grpc.ConsensusServiceStub(c) for c in channels]

threads = []
for stub in stubs:
    for _ in range(5):   # maxConcurrentCallsPerConnection
        t = threading.Thread(target=subscribe, args=(stub,), daemon=True)
        threads.append(t)

# Launch all 1000 subscriptions simultaneously
for t in threads:
    t.start()

# After ~1 second, all safety-check Mono.delay timers expire simultaneously,
# firing up to 1000 × 13 = 13,000 DB queries in ~240 ms.
# Monitor DB connection pool saturation and mirror node response latency.
time.sleep(10)
```