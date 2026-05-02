### Title
Unbounded gRPC Subscription Accumulation via Missing Duration Limit in `CompositeTopicListener.listen()`

### Summary
`CompositeTopicListener.listen()` returns a `Flux<TopicMessage>` with no maximum subscription duration enforced. Because `TopicMessageFilter` makes `endTime` and `limit` optional (defaulting to null/0 = unlimited), and no per-IP or global concurrent-connection cap exists in the gRPC layer, an unauthenticated attacker can open arbitrarily many long-lived connections — each carrying up to 5 subscriptions — and gradually exhaust server-side resources across mirror node replicas.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` (line 43–53) converts the client's `ConsensusTopicQuery` into a `TopicMessageFilter` via `toFilter()`. Neither `endTime` nor `limit` is required by the proto or validated as mandatory: [1](#0-0) 

`TopicMessageFilter` declares both fields as optional — `endTime` defaults to `null`, `limit` defaults to `0` (meaning unlimited): [2](#0-1) 

`CompositeTopicListener.listen()` delegates to the underlying listener and applies only a topic-ID/timestamp filter and a metrics hook — **no `.timeout()`, no `.take(duration)`, no subscription-count gate**: [3](#0-2) 

**Root cause:** The `Flux` returned by `listen()` is unbounded in time when the client omits `consensusEndTime` and `limit`. The subscription lives until the client disconnects, an error occurs, or the optional `endTime` is reached — none of which are guaranteed.

**Existing checks and why they fail:**

- `maxConcurrentCallsPerConnection = 5` (NettyProperties) limits calls *per TCP connection*, not total connections: [4](#0-3) 
  An attacker opens thousands of connections, each carrying 5 subscriptions.

- The nginx `grpc_read_timeout 600s` resets on every received message: [5](#0-4) 
  Subscribing to any active topic (or submitting messages to keep the topic live) prevents the timeout from firing.

- The GCP backend `maxRatePerEndpoint: 250` throttles the *rate* of new requests, not the count of *concurrent* open streams: [6](#0-5) 

- No authentication is required to call `subscribeTopic`. No per-IP connection limit exists in `GrpcProperties` or `ListenerProperties`: [7](#0-6) [8](#0-7) 

### Impact Explanation
Each open subscription holds a Reactor scheduler thread slot, a Netty channel, and (for POLL/SHARED_POLL modes) a database polling chain. Tens of thousands of concurrent subscriptions across a node exhaust file descriptors, thread-pool capacity, and heap. Because no authentication or per-client cap exists, the same attack can be replayed against every mirror node replica in the cluster. Degrading ≥30% of replicas causes legitimate subscribers to receive errors or stale data, meeting the stated medium-severity threshold.

### Likelihood Explanation
The attack requires only a standard gRPC client (e.g., `grpcurl`, the Hedera Java SDK, or a raw HTTP/2 client). No credentials, no privileged network position, and no prior knowledge beyond the public proto schema are needed. A single attacker machine with a modest number of source ports can open thousands of HTTP/2 connections. The attack is repeatable and can be sustained indefinitely as long as the topic receives occasional messages.

### Recommendation
1. **Enforce a server-side maximum subscription duration** — apply `.timeout(maxDuration)` in `CompositeTopicListener.listen()` or in `TopicMessageService`, configurable via `ListenerProperties`.
2. **Cap total concurrent subscriptions globally and per-IP** — maintain an `AtomicInteger` counter; reject new subscriptions above a configurable threshold.
3. **Cap connections per IP at the Netty/load-balancer level** — configure `maxConnectionAge` and `maxConnectionIdle` on the Netty gRPC server, and add an IP-based connection-rate limit at the GCP gateway.
4. **Make `endTime` or `limit` mandatory** — reject queries that omit both, forcing clients to bound their own subscriptions.

### Proof of Concept
```bash
# Open 200 connections, each with 5 concurrent unlimited subscriptions (1000 total per node)
# Repeat against each mirror node replica

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d '{
      "topicID": {"topicNum": 1},
      "consensusStartTime": {"seconds": 0}
    }' <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Each subscription has no endTime and no limit — it stays open indefinitely.
# With enough parallel attackers targeting ≥30% of replicas, the cluster
# exhausts Netty channel capacity and Reactor thread pools, causing
# RESOURCE_EXHAUSTED errors for legitimate subscribers.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-73)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

        if (query.hasTopicID()) {
            filter.topicId(EntityId.of(query.getTopicID()));
        }

        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }

        if (query.hasConsensusEndTime()) {
            long endTime = convertTimestamp(query.getConsensusEndTime());
            filter.endTime(endTime);
        }

        return filter.build();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-41)
```java
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/CompositeTopicListener.java (L35-44)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        if (!listenerProperties.isEnabled()) {
            return Flux.empty();
        }

        return getTopicListener()
                .listen(filter)
                .filter(t -> filterMessage(t, filter))
                .doOnNext(this::recordMetric);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** docker-compose.yml (L225-226)
```yaml
        # Setting 600s read timeout for topic subscription. When the client receives a message the timeout resets to 0.
        location = /com.hedera.mirror.api.proto.ConsensusService/subscribeTopic { grpc_read_timeout 600s; grpc_pass grpc://grpc_host; }
```

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L17-30)
```java
public class GrpcProperties {

    private boolean checkTopicExists = true;

    @NotNull
    private Duration endTimeInterval = Duration.ofSeconds(30);

    @Min(1)
    private int entityCacheSize = 50_000;

    @NotNull
    @Valid
    private NettyProperties netty = new NettyProperties();
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L17-43)
```java
public class ListenerProperties {

    private boolean enabled = true;

    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;

    @Min(32)
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);

    @Min(4)
    @Max(256)
    private int prefetch = 48;

    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```
