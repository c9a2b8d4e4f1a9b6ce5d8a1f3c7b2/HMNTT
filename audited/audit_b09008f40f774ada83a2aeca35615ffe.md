### Title
Unbounded Concurrent Subscription Amplification via Absent Global Rate Limiting in `subscribeTopic` / `retrieve()`

### Summary
The gRPC `subscribeTopic` endpoint accepts an unlimited number of connections from any unauthenticated client. The only concurrency control, `maxConcurrentCallsPerConnection` (default: 5), is scoped per TCP connection, not per IP or globally. An attacker can open an arbitrary number of TCP connections and saturate the server with thousands of independent subscriptions, each independently driving database polling through `retrieve()`, exhausting the DB connection pool and server resources.

### Finding Description
**Entry point:** `ConsensusController.subscribeTopic()` — `grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java`, lines 43–53. No authentication, no IP check, no global subscription cap is applied before delegating to `topicMessageService.subscribeTopic(filter)`.

**Service layer:** `TopicMessageServiceImpl.subscribeTopic()` — `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, lines 59–92. The `subscriberCount` AtomicLong (line 48) is a **Micrometer gauge only** — it is never checked against any ceiling. Each call unconditionally creates a new `TopicContext`, a new historical `Flux` via `topicMessageRetriever.retrieve(filter, true)` (line 63), and a new live listener `Flux` (line 64).

**Retriever interface:** `grpc/src/main/java/org/hiero/mirror/grpc/retriever/TopicMessageRetriever.java`, line 17 — `retrieve(TopicMessageFilter filter, boolean throttled)`. The `throttled` flag only controls polling frequency/page size within a single subscription; it does not limit how many concurrent calls to `retrieve()` can exist simultaneously.

**The only concurrency guard:** `GrpcConfiguration.java` lines 28–35 sets `maxConcurrentCallsPerConnection` (default 5, `NettyProperties.java` line 14). This is a Netty-level per-connection limit. An attacker opens C connections → C × 5 = 5C concurrent subscriptions, each independently polling the database.

**Root cause:** The system assumes a small, well-behaved subscriber population. There is no per-IP connection limit, no global subscription ceiling, and no authentication requirement at any layer of the gRPC stack.

### Impact Explanation
Each active subscription drives independent periodic database queries through `PollingTopicMessageRetriever` or Redis listener fan-out. With thousands of concurrent subscriptions:
- The database connection pool (`hiero.mirror.grpc.db`) is exhausted, causing legitimate queries to queue or fail.
- JVM heap is consumed by thousands of `TopicContext`, `Flux`, and `Scheduler` objects.
- The `boundedElastic` scheduler used for safety-check polling (`TopicMessageServiceImpl.java` line 70) is saturated.
- The result is a full denial of service for all legitimate subscribers on the mirror node.

Severity: **High** — complete service unavailability for all users of the gRPC API.

### Likelihood Explanation
No special privileges are required. The gRPC port (default 5600) is publicly exposed. A single attacker machine can open thousands of TCP connections and issue 5 `subscribeTopic` RPCs per connection using any standard gRPC client (e.g., `grpc-java`, `grpcurl`, Python `grpcio`). The attack is trivially scriptable, repeatable, and requires no knowledge of topic contents or credentials.

### Recommendation
1. **Enforce a global concurrent-subscription cap**: Check `subscriberCount` against a configurable maximum in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP subscription limiting**: Use a `ServerInterceptor` (alongside the existing `GrpcInterceptor`) to track and cap active subscriptions per remote IP using a `ConcurrentHashMap<String, AtomicInteger>`.
3. **Add a global connection limit**: Configure `NettyServerBuilder.maxConnectionAge` and `maxConnectionIdle` to reclaim idle connections, and set `maxConcurrentCallsPerConnection` to a lower value or add a total-connections cap.
4. **Require authentication**: Integrate token/API-key validation in the interceptor so anonymous bulk subscription is not possible.

### Proof of Concept
```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, mirror_network_service_pb2

TARGET = "mirror-node-grpc-host:5600"
TOPIC_ID = "0.0.12345"  # any valid topic
CONNECTIONS = 500
CALLS_PER_CONN = 5  # matches maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    threads = []
    for _ in range(CALLS_PER_CONN):
        req = build_subscribe_request(TOPIC_ID)
        t = threading.Thread(target=lambda: list(stub.subscribeTopic(req)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

threads = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Result: 2500 concurrent subscriptions; DB pool exhausted; legitimate subscribers receive errors
```