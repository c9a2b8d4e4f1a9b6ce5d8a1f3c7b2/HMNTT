### Title
Unbounded Concurrent gRPC Subscription Streams Enable DoS via DB Connection Pool Exhaustion

### Summary
`PollingTopicMessageRetriever.retrieve()` imposes no per-user, per-IP, or global subscription count limit. The only server-side guard — `maxConcurrentCallsPerConnection = 5` — is scoped per TCP connection, not globally. An unauthenticated attacker can open an unbounded number of TCP connections, each carrying 5 long-lived polling streams, exhausting the database connection pool and denying service to legitimate subscribers.

### Finding Description
**Exact code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) accepts any unauthenticated `ConsensusTopicQuery`, builds a `TopicMessageFilter`, and calls `topicMessageService.subscribeTopic()` with no connection counting or rate-limiting check.

`PollingTopicMessageRetriever.retrieve()` (lines 45–63) immediately creates a `PollingContext` and returns a `Flux` that:
- Polls `topicMessageRepository.findByFilter()` every 2 seconds (throttled) or 20 ms (unthrottled) — each poll acquires a DB connection from the HikariCP pool.
- Retries with `Retry.backoff(Long.MAX_VALUE, ...)` (line 58) — effectively infinite retries.
- Times out only after 60 seconds of *no emissions* (line 59) — for a live topic with messages, the stream never times out.

**The only server-level guard:**

`GrpcConfiguration.java` line 33 sets `maxConcurrentCallsPerConnection(5)` via `NettyProperties.maxConcurrentCallsPerConnection = 5`. This is a **per-connection** limit. No `maxConnections()` call is made on the `NettyServerBuilder`, so the total number of TCP connections is unbounded.

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection` constitutes a global subscription cap. It does not — it only limits multiplexed streams per HTTP/2 connection. An attacker opens N connections × 5 streams = N×5 concurrent polling streams with no server-side ceiling.

**Why existing checks fail:**
- No authentication or API key required to call `subscribeTopic`.
- No global active-subscription counter anywhere in the gRPC module (confirmed by grep: only `maxConcurrentCallsPerConnection` and `maxConnections` references exist in `GrpcConfiguration.java` and `NettyProperties.java`).
- No per-IP connection limit configured.
- The `timeout` only fires on idle streams; a stream subscribed to a busy topic never idles.

### Impact Explanation
Each attacker-controlled stream issues a DB query every 2 seconds. With a HikariCP pool of typical size (e.g., 10–20 connections), as few as ~10–20 concurrent attacker streams fully saturate the pool. Legitimate subscribers then queue indefinitely waiting for a DB connection, causing their streams to stall or time out. At higher stream counts (hundreds), the `boundedElastic` scheduler queue fills, JVM heap pressure rises from accumulated `PollingContext` objects and Reactor chain state, and file-descriptor limits are approached. The result is complete denial of topic message delivery to all legitimate clients — directly preventing gossip of transactions from being received.

### Likelihood Explanation
No privileges, credentials, or special network position are required. Any internet-reachable gRPC port (default 5600) is sufficient. A single attacker machine can open hundreds of TCP connections using standard gRPC client libraries (e.g., `grpc-java`, `grpcurl`, Python `grpcio`) in a simple loop. The attack is trivially repeatable and scriptable, and the attacker need not send any data after the initial `subscribeTopic` RPC — the server does all the work.

### Recommendation
1. **Add a global active-subscription counter** in `TopicMessageService` or `ConsensusController`. Reject new subscriptions with `RESOURCE_EXHAUSTED` when the counter exceeds a configurable ceiling.
2. **Add a per-source-IP connection/stream limit** via a gRPC `ServerInterceptor` that tracks active calls per remote address and returns `RESOURCE_EXHAUSTED` when exceeded.
3. **Set a total connection cap** on the Netty server: add `serverBuilder.maxConnectionAge(...)` and `serverBuilder.maxConnections(...)` (via `NettyServerBuilder`) in `GrpcConfiguration.java`.
4. **Deploy an ingress-layer rate limiter** (e.g., Envoy, nginx) in front of port 5600 to limit new connection rates per IP before requests reach the JVM.

### Proof of Concept
```python
import grpc
import threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from hedera.mirror.api.proto import consensus_topic_query_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-host:5600"
TOPIC_NUM = 1  # any existing topic

def flood():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_topic_query_pb2.ConsensusTopicQuery()
    query.topicID.topicNum = TOPIC_NUM
    # Open 5 streams per connection (maxConcurrentCallsPerConnection limit)
    streams = [stub.subscribeTopic(query) for _ in range(5)]
    # Keep streams alive by consuming lazily
    for s in streams:
        try:
            next(iter(s))
        except Exception:
            pass

# Open hundreds of connections from a single host
threads = [threading.Thread(target=flood) for _ in range(200)]
for t in threads:
    t.start()
# Result: 200 connections × 5 streams = 1000 concurrent DB-polling streams
# DB connection pool exhausted; legitimate subscribers receive no messages
```