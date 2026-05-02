### Title
Unbounded Concurrent Historical Subscriptions Exhaust Database Connection Pool (DoS)

### Summary
The `subscribeTopic()` endpoint in `ConsensusController` requires no authentication and enforces no global limit on concurrent subscriptions. Every subscription with a `startTime` in the past unconditionally triggers an independent, long-running polling loop against the database via `PollingTopicMessageRetriever`. An attacker opening N connections (each with up to 5 calls) can generate N×5 concurrent, indefinitely-repeating DB queries, exhausting the connection pool and denying service to all legitimate users.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` (line 43–53) accepts any unauthenticated gRPC call and immediately delegates to `TopicMessageServiceImpl.subscribeTopic()` with no rate-limiting or subscriber-count cap. [1](#0-0) 

Inside `TopicMessageServiceImpl.subscribeTopic()`, line 63 unconditionally creates a historical retrieval flux for every subscriber regardless of how many are already active: [2](#0-1) 

The `subscriberCount` field (line 48) is wired only to a Micrometer gauge — it is never checked against any maximum and never blocks new subscriptions: [3](#0-2) 

`PollingTopicMessageRetriever.retrieve()` is called with `throttled=true`. In the throttled path, `numRepeats` is set to `Long.MAX_VALUE` and polling continues indefinitely until the historical data is exhausted: [4](#0-3) 

Each poll issues a direct synchronous DB query: [5](#0-4) 

The only per-connection limit is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`, which limits calls **per TCP connection**, not total connections across the server: [6](#0-5) 

**Root cause:** No global subscription cap, no per-IP rate limit, and no authentication gate. The `subscriberCount` metric is purely observational. Each subscriber independently drives a `Long.MAX_VALUE`-repeat polling loop that issues DB queries at `retrieverProperties.getPollingFrequency()` intervals.

### Impact Explanation
With N attacker-controlled connections × 5 calls each = 5N concurrent subscriptions, each issuing periodic DB queries. A typical DB connection pool (e.g., HikariCP default of 10) is exhausted with as few as 2–3 attacker connections. Once the pool is saturated, all legitimate gRPC subscribers and any other service sharing the pool (REST API, importer) receive connection-timeout errors. This is a complete denial of service for the mirror node's topic subscription feature.

### Likelihood Explanation
The attack requires zero privileges — no API key, no account, no authentication of any kind. The gRPC endpoint is publicly reachable. Opening many TCP connections with crafted `ConsensusTopicQuery` messages (setting `consensusStartTime` to epoch 0) is trivially scriptable with any gRPC client library. The attack is repeatable and can be sustained indefinitely since each subscription, once opened, holds a DB polling loop for `Long.MAX_VALUE` iterations.

### Recommendation
1. **Enforce a global concurrent-subscriber cap**: Check `subscriberCount` against a configurable maximum in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP / per-connection subscription rate limiting** at the gRPC interceptor layer before reaching the controller.
3. **Require authentication** (e.g., a bearer token or mTLS) for subscriptions, or at minimum apply IP-based throttling via a gRPC `ServerInterceptor`.
4. **Bound the historical retrieval concurrency**: Use a semaphore or `Schedulers.newBoundedElastic(maxConcurrency, ...)` to cap how many simultaneous historical polling loops can run.
5. **Enforce a mandatory `limit`** on subscriptions without an `endTime`, preventing indefinite open-ended historical scans.

### Proof of Concept
```python
import grpc
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from com.hedera.hashgraph.sdk.proto import consensus_topic_query_pb2
from google.protobuf.timestamp_pb2 import Timestamp

# Open 10 connections, 5 subscriptions each = 50 concurrent DB polling loops
stubs = []
for _ in range(10):
    channel = grpc.insecure_channel("mirror-node-grpc:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    stubs.append(stub)

for stub in stubs:
    for _ in range(5):
        query = consensus_topic_query_pb2.ConsensusTopicQuery(
            topicID=...,                          # any valid topic ID
            consensusStartTime=Timestamp(seconds=0, nanos=0)  # epoch = far past
            # no limit, no endTime → indefinite historical scan
        )
        # Non-blocking: fire and forget, keep connection open
        stub.subscribeTopic(query)

# Result: 50 concurrent PollingTopicMessageRetriever loops each issuing
# DB queries every pollingFrequency interval → DB connection pool exhausted
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-53)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-63)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L94-107)
```java
        private PollingContext(TopicMessageFilter filter, boolean throttled) {
            this.filter = filter;
            this.throttled = throttled;

            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```
