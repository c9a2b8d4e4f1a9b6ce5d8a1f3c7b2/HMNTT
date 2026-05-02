### Title
Unbounded `endTime` Enables Indefinite Subscription Resource Exhaustion via `pastEndTime()` Polling Loop

### Summary
`TopicMessageFilter.endTime` has no upper-bound validation, allowing any unprivileged caller to supply a far-future value (e.g., `Long.MAX_VALUE` nanoseconds ≈ year 2262). This causes `pastEndTime()` to schedule a `RepeatSpec` with up to `Long.MAX_VALUE` iterations on `Schedulers.boundedElastic()`, polling every 30 seconds indefinitely, holding the gRPC stream and scheduler resources open for the lifetime of the server. An attacker opening many such subscriptions exhausts the bounded elastic thread pool, starving legitimate requests.

### Finding Description

**Validation gap — `TopicMessageFilter`** [1](#0-0) 

`endTime` is a plain `Long` with no `@Max` or range constraint. The only guard is `isValidEndTime()` which only asserts `endTime > startTime` — a far-future value like `Long.MAX_VALUE` passes trivially.

**`pastEndTime()` — unbounded repeat loop** [2](#0-1) 

When `endTime != null`, a `RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE).withFixedDelay(endTimeInterval)` is created. With `endTimeInterval = 30s` (default), this schedules a check every 30 seconds for up to `Long.MAX_VALUE` iterations — effectively forever.

**`isComplete()` — never returns `true` for far-future `endTime`** [3](#0-2) 

`isComplete()` returns `true` only when `Instant.ofEpochSecond(0, endTime).plus(endTimeInterval).isBefore(Instant.now())`. For `endTime = Long.MAX_VALUE` nanoseconds (year 2262), this condition is never satisfied in practice.

**Subscription wiring — stream stays open** [4](#0-3) 

The live/safety-check flux runs under `.takeUntilOther(pastEndTime(topicContext))`. Since `pastEndTime` never completes, the entire subscription — including the `Schedulers.boundedElastic()` worker used by `safetyCheck` — is held open indefinitely. [5](#0-4) 

**`subscriberCount` provides no enforcement** [6](#0-5) 

`subscriberCount` is a Micrometer gauge only — it is never checked against a maximum, so there is no server-side cap on concurrent long-lived subscriptions.

### Impact Explanation
Each malicious subscription permanently occupies a gRPC server stream, a `RepeatSpec` scheduler slot on `Schedulers.boundedElastic()`, and associated memory. The bounded elastic pool has a finite thread ceiling; flooding it with far-future-`endTime` subscriptions starves legitimate subscribers and safety-check tasks, causing request queuing, timeouts, and effective denial of service for all topic consumers. Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation
The gRPC `subscribeTopic` endpoint is publicly reachable by design. No credentials, roles, or special permissions are needed. The exploit requires only a standard gRPC client call with a crafted `endTime` field. It is trivially scriptable and repeatable; a single attacker with a modest number of parallel connections can exhaust the server.

### Recommendation
1. **Add an upper-bound constraint on `endTime`** in `TopicMessageFilter` — e.g., reject values more than a configurable window (e.g., 24–48 hours) beyond `Instant.now()`:
   ```java
   @AssertTrue(message = "End time must not be more than 48 hours in the future")
   public boolean isValidEndTimeBound() {
       return endTime == null ||
           Instant.ofEpochSecond(0, endTime)
               .isBefore(Instant.now().plus(Duration.ofHours(48)));
   }
   ```
2. **Enforce a maximum concurrent subscriber limit** — check `subscriberCount` against a configurable cap in `subscribeTopic` and reject with a gRPC `RESOURCE_EXHAUSTED` status when exceeded.
3. **Cap the `RepeatSpec` iteration count** to a finite, operationally meaningful value rather than `Long.MAX_VALUE`, as a defense-in-depth measure.

### Proof of Concept
```java
// gRPC client pseudocode
ConsensusTopicQuery query = ConsensusTopicQuery.newBuilder()
    .setTopicID(TopicID.newBuilder().setTopicNum(1).build())
    .setConsensusStartTime(Timestamp.newBuilder().setSeconds(0).build())
    // endTime = Long.MAX_VALUE nanoseconds from epoch (year 2262)
    .setConsensusEndTime(Timestamp.newBuilder()
        .setSeconds(Long.MAX_VALUE / 1_000_000_000L)
        .setNanos((int)(Long.MAX_VALUE % 1_000_000_000L))
        .build())
    .build();

// Open N parallel streams — each holds a boundedElastic slot forever
for (int i = 0; i < N; i++) {
    stub.subscribeTopic(query, noopObserver());
}
// After N connections, legitimate subscribeTopic calls queue/timeout
// because boundedElastic is saturated and isComplete() never fires
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-46)
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

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-55)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L72-73)
```java
        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-215)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }

            if (filter.getEndTime() < startTime) {
                return true;
            }

            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
        }
```
