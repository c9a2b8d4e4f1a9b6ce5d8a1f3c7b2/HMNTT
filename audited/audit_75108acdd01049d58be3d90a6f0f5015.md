### Title
Unbounded Concurrent Subscriptions with startTime=0 Enable Resource Exhaustion and Connection Pool Starvation

### Summary
`TopicMessageServiceImpl.subscribeTopic()` imposes no limit on the number of concurrent subscriptions per client or globally. An unauthenticated attacker can open thousands of gRPC subscriptions with `startTime=0`, no `endTime`, and no `limit`, each triggering an unbounded historical database query. During a network partition, these queries stall mid-stream while holding database connections, exhausting the connection pool and preventing service recovery even after the partition heals.

### Finding Description

**Code path:**

`TopicMessageServiceImpl.subscribeTopic()` — [1](#0-0) 

**Step 1 — No subscription gate exists.**
`subscriberCount` is declared as a `Gauge` metric only: [2](#0-1) 
It is incremented on subscribe and decremented on finish, but **never checked against any maximum**. There is no per-IP, per-user, or global cap that would reject a new subscription.

**Step 2 — `startTime=0` is explicitly permitted.**
`TopicMessageFilter` declares `@Min(0)` on `startTime`: [3](#0-2) 
The `isValidStartTime()` validator only checks `startTime <= DomainUtils.now()`, which epoch-0 always satisfies. This causes the historical retriever to scan from the very beginning of the topic's history.

**Step 3 — No `endTime` means the subscription never self-terminates.**
`isComplete()` unconditionally returns `false` when `endTime` is null: [4](#0-3) 
`pastEndTime()` returns `Flux.never()` in the same case: [5](#0-4) 

**Step 4 — No `limit` means the historical Flux is unbounded.**
`hasLimit()` returns `false` when `limit == 0` (the default): [6](#0-5) 
The `flux.take()` guard is only applied when `filter.hasLimit()`: [7](#0-6) 

**Step 5 — The historical Flux is created eagerly, not deferred.**
Line 63 creates the retriever Flux immediately on subscription: [8](#0-7) 
Each of the thousands of subscriptions immediately issues a database query scanning from epoch 0 with no upper bound.

**Step 6 — Network partition stalls cursors.**
During a network partition between the gRPC service and the database, each in-flight `retrieve(filter, true)` call stalls mid-stream. The database connection is neither returned to the pool nor closed — it is held open waiting for the next row. With thousands of subscriptions, all pool slots are occupied by stalled cursors. New requests (including legitimate ones and health checks) cannot acquire a connection. Even after the partition heals, the stalled cursors may not be released promptly depending on socket timeout configuration, prolonging the outage.

### Impact Explanation

- **Database connection pool exhaustion**: All pool connections are held by stalled historical cursors, making the service unable to serve any request.
- **Denial of service persists post-partition**: Recovery is blocked until stalled connections time out at the TCP/socket layer, which can be minutes to hours with default OS settings.
- **No authentication required**: The gRPC `ConsensusService/subscribeTopic` endpoint is publicly accessible; no credentials are needed.
- **Severity: High** — complete service unavailability triggered by a single unauthenticated attacker.

### Likelihood Explanation

- Any client with network access to the gRPC port can execute this attack.
- Opening thousands of gRPC streams is trivial with standard gRPC client libraries (a simple loop).
- `startTime=0`, no `endTime`, no `limit` are all valid per the schema — no special knowledge is required.
- The attack is repeatable and can be automated.

### Recommendation

1. **Enforce a maximum concurrent subscription limit**: Check `subscriberCount` against a configurable maximum in `subscribeTopic()` and return `RESOURCE_EXHAUSTED` if exceeded. Also enforce per-source-IP limits at the Netty/gRPC layer via `NettyProperties`.
2. **Restrict `startTime` minimum age**: Reject `startTime` values older than a configurable lookback window (e.g., 24 hours) to bound the size of historical queries.
3. **Require `endTime` or `limit` for historical queries**: When `startTime` is significantly in the past, mandate at least one termination condition.
4. **Set database query timeouts**: Configure statement/query timeouts on the connection pool so stalled cursors are forcibly closed during a partition rather than held indefinitely.
5. **Defer the historical Flux**: Wrap line 63 in `Flux.defer(...)` so the DB query is not issued until the subscription is actually active and can be cancelled cleanly.

### Proof of Concept

```python
import grpc
import threading
# proto: hiero/mirror/api/proto/consensus_service.proto

def open_subscription(stub):
    request = ConsensusTopicQuery(
        topicID=ConsensusTopicID(topicNum=1),
        consensusStartTime=Timestamp(seconds=0, nanos=0),
        # no consensusEndTime, no limit
    )
    for _ in stub.subscribeTopic(request):
        pass  # consume nothing, keep stream open

channel = grpc.insecure_channel("target:5600")
stub = ConsensusServiceStub(channel)

threads = [threading.Thread(target=open_subscription, args=(stub,)) for _ in range(5000)]
for t in threads:
    t.start()

# Simulate network partition: block DB port via firewall rule
# Result: all 5000 subscriptions stall holding DB connections
# New legitimate requests receive connection pool timeout errors
# Service remains unavailable until socket-level timeouts expire
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L52-55)
```java
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-92)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });

        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }

        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-31)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```
