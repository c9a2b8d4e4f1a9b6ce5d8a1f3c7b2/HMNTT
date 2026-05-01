### Title
Unbounded Resource Exhaustion via Unlimited Historical Topic Subscription (limit=0, startTime=genesis)

### Summary
The `subscribeTopic()` endpoint in `TopicMessageServiceImpl` accepts `ConsensusTopicQuery` with `limit=0` and `startTime=0` (genesis) from any unauthenticated caller. Because `hasLimit()` returns `false` for `limit=0`, no `.take()` cap is applied, and with no `endTime`, the stream never terminates. Multiple concurrent connections of this form exhaust database connections, memory, and CPU, denying service to legitimate subscribers.

### Finding Description

**Proto contract (by design, but unguarded):**
The proto explicitly documents `limit=0` as "return messages indefinitely." [1](#0-0) 

**`hasLimit()` gate — returns false for limit=0:** [2](#0-1) 

**Consequence in `subscribeTopic()` — `.take()` is never applied:** [3](#0-2) 

**`startTime=0` passes all validation** — `@Min(0)` allows it, and `isValidStartTime()` only checks `startTime <= DomainUtils.now()`, which epoch-zero satisfies: [4](#0-3) 

**No `endTime` → `pastEndTime()` returns `Flux.never()` → stream never terminates:** [5](#0-4) 

**Full pipeline per connection:**
Each subscription triggers a full historical page-scan from genesis via `topicMessageRetriever.retrieve(filter, true)`, then transitions to an indefinite live listener: [6](#0-5) 

**`subscriberCount` is only a metric gauge — not enforced as a limit:** [7](#0-6) 

**No authentication on the gRPC endpoint** — `ConsensusController.subscribeTopic()` maps the query directly to a filter with no auth check: [8](#0-7) 

**Retriever throttle does not bound total subscription lifetime** — `RetrieverProperties.timeout` (60 s) governs per-poll cycles, not the overall stream duration: [9](#0-8) 

### Impact Explanation
Each malicious connection holds: one or more R2DBC database connections (paging through all historical messages), a Netty I/O thread slot, a `boundedElastic` scheduler thread (safety-check path), and heap memory for the reactive pipeline. With no per-IP or global subscriber cap enforced in code, an attacker opening tens of such connections can saturate the R2DBC connection pool and Netty thread pool, causing legitimate subscribers to time out or be rejected. Because the live phase never terminates (no `endTime`, no `limit`), connections persist indefinitely unless the client disconnects.

### Likelihood Explanation
The gRPC endpoint is publicly accessible with no authentication. The exploit requires only a standard gRPC client (e.g., `grpcurl` or the Hedera Java SDK). The parameters `limit=0` and `startTime` at epoch zero are explicitly documented as valid in the proto spec, so no special knowledge is needed. The attack is trivially repeatable and scriptable from a single machine or distributed across multiple IPs.

### Recommendation
1. **Enforce a maximum concurrent subscriber limit** — check `subscriberCount` against a configurable threshold before accepting a new subscription and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Enforce a maximum historical window** — reject or cap queries where `startTime` is more than a configurable duration before `now()` (e.g., 30 days), or require `endTime` when `startTime` is in the distant past.
3. **Require a non-zero `limit` for open-ended historical queries** — if `startTime` is before a threshold and `endTime` is absent, mandate `limit > 0`.
4. **Add per-IP connection rate limiting** at the Netty/gRPC interceptor layer.
5. **Enforce a maximum subscription lifetime** — terminate streams that have been open beyond a configurable wall-clock duration.

### Proof of Concept
```bash
# Install grpcurl, point at the mirror node gRPC endpoint
# Send limit=0 (omitted = 0 in proto3) and startTime at epoch 0

for i in $(seq 1 50); do
  grpcurl -plaintext \
    -d '{
      "topicID": {"topicNum": 1000},
      "consensusStartTime": {"seconds": 0, "nanos": 0}
    }' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    > /dev/null &
done

# Each background process holds a persistent gRPC stream:
# 1. Pages through ALL historical messages from genesis (DB connection held)
# 2. Then listens indefinitely for new messages (stream never closed)
# After ~50 connections the R2DBC pool is exhausted;
# legitimate subscribers receive UNAVAILABLE or hang indefinitely.
```

### Citations

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L23-25)
```text
    // The maximum number of messages to receive before stopping. If not set or set to zero it will return messages
    // indefinitely.
    uint64 limit = 4;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L28-51)
```java
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

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-73)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-131)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }

        return Flux.empty()
                .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                        .withFixedDelay(grpcProperties.getEndTimeInterval()));
    }
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L27-28)
```java
    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```
