### Title
Unbounded gRPC Subscription Resource Exhaustion via Missing Global Connection and Subscription Limits

### Summary
`CompositeTopicListener.listen()` allocates a new reactive operator chain per subscription with no global cap on concurrent subscriptions or connections. The only guard, `maxConcurrentCallsPerConnection = 5`, is scoped per TCP connection, not globally, so an attacker opening many connections multiplies subscriptions without bound. Under the `POLL` listener type each subscription additionally spawns an independent database polling loop, exhausting the DB connection pool; under all types, unbounded `onBackpressureBuffer(16384)` allocations and `TopicContext` objects accumulate until heap is exhausted.

### Finding Description
**Code path:**

- `GrpcConfiguration.java:33` — only `maxConcurrentCallsPerConnection(5)` is applied; no `maxConnections`, no `maxConnectionAge`, no global subscription ceiling.
- `CompositeTopicListener.java:35-44` — `listen()` unconditionally builds a new `Flux` chain (`.filter(t -> filterMessage(t, filter))` + `.doOnNext(this::recordMetric)`) for every call.
- `SharedTopicListener.java:24` — every subscriber receives its own `onBackpressureBuffer(listenerProperties.getMaxBufferSize())` (default 16 384 slots).
- `TopicMessageServiceImpl.java:48,89-90` — `subscriberCount` is incremented/decremented as a Micrometer gauge but is **never checked** to reject new subscriptions.
- `PollingTopicListener.java:34-49` — under `POLL` type, each `listen()` call creates a new `PollingContext` and a `Flux.defer(() -> poll(context)).repeatWhen(...)` loop that issues a DB query every 500 ms independently.

**Root cause:** The design assumes an external load-balancer or network policy will cap connections. No such enforcement exists in the application layer. `maxConcurrentCallsPerConnection` is a Netty per-H2-stream limit; an attacker opens C connections and gets 5C concurrent live subscriptions.

**Exploit flow:**
1. Attacker opens C gRPC connections (no server-side connection limit).
2. Each connection issues 5 `subscribeTopic` RPCs (maxConcurrentCallsPerConnection = 5).
3. Each RPC causes `CompositeTopicListener.listen()` to allocate a new reactive chain + `TopicContext` + backpressure buffer.
4. Under `POLL` type: 5C independent DB polling loops fire every 500 ms, exhausting the HikariCP pool and starving legitimate queries.
5. Under any type: with sufficient C, heap fills with `TopicContext` objects, buffer arrays, and operator state, triggering GC pressure then OOM.

### Impact Explanation
Under `POLL` listener type, DB connection pool exhaustion occurs before OOM, causing all historical and live topic queries to fail with connection-timeout errors — effectively halting topic message delivery for all legitimate subscribers. Under `REDIS`/`SHARED_POLL`, the impact is heap exhaustion and JVM crash. Either outcome terminates the mirror node's gRPC service, preventing clients from receiving transaction confirmation events via HCS topic subscriptions.

### Likelihood Explanation
The gRPC port (default 5600) is publicly reachable by design — any SDK client can call `subscribeTopic`. No authentication is required. A single attacker machine can open thousands of TCP connections and issue 5 subscriptions each using standard gRPC tooling (e.g., `grpcurl`, a custom Go/Java client). The attack is trivially repeatable and requires no special knowledge beyond the public protobuf API.

### Recommendation
1. **Add a global concurrent-subscription limit** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add a per-IP or per-connection subscription limit** at the Netty layer via a `ServerInterceptor`.
3. **Configure `maxConnectionAge` and `maxConnections`** in `GrpcConfiguration` via `NettyServerBuilder` to bound total open connections.
4. **Expose `maxSubscribers` in `ListenerProperties`** so operators can tune the ceiling without code changes.
5. For `POLL` type specifically, enforce a hard cap on concurrent polling loops to protect the DB connection pool.

### Proof of Concept
```python
# Requires: pip install grpcio grpcio-tools
import grpc, threading, time
from hedera import consensus_service_pb2_grpc, mirror_network_service_pb2 as pb

TARGET = "mirror.node.host:5600"
CONNECTIONS = 500   # 500 connections × 5 calls = 2500 subscriptions

def flood(i):
    ch = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(ch)
    req = pb.ConsensusTopicQuery()
    req.topicID.topicNum = 1234
    # Open 5 subscriptions per connection (maxConcurrentCallsPerConnection)
    streams = [stub.subscribeTopic(req) for _ in range(5)]
    # Keep streams alive
    time.sleep(300)

threads = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for t in threads: t.start()
# Result: 2500 concurrent subscriptions; under POLL type, 2500 DB queries/500ms
# Monitor: watch JVM heap and DB connection pool — both exhaust within minutes
```