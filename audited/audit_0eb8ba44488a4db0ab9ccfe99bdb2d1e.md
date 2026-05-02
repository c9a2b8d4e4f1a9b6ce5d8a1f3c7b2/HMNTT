### Title
Unauthenticated gRPC Subscriber Can Force Full Historical Topic Scan via Epoch-Zero consensusStartTime

### Summary
An unprivileged external user can send a `subscribeTopic` gRPC request with `consensusStartTime = {seconds: 0, nanos: 0}` and no limit, causing `convertTimestamp()` to produce `startTime = 0`. This value passes all validation in `TopicMessageFilter` and results in a database query of `WHERE topic_id = ? AND consensus_timestamp >= 0`, which returns every message ever posted to the topic. There is no authentication, no rate limiting, and no enforced minimum start time on the gRPC endpoint.

### Finding Description

**Exact code path:**

1. `ConsensusController.subscribeTopic()` has no authentication or rate-limiting guard. [1](#0-0) 

2. `toFilter()` calls `convertTimestamp()` only when `hasConsensusStartTime()` is true. In proto3, `Timestamp` is a message type, so setting `{seconds:0, nanos:0}` explicitly makes `hasConsensusStartTime()` return `true`. [2](#0-1) 

3. `convertTimestamp()` only guards against overflow (`seconds >= 9223372035L`). For `seconds=0, nanos=0` it falls through to `DomainUtils.timestampInNanosMax(timestamp)` which returns `0`. [3](#0-2) 

4. `TopicMessageFilter` validation: `@Min(0)` allows `startTime = 0`, and `isValidStartTime()` only checks `startTime <= DomainUtils.now()` — epoch 0 trivially satisfies this. [4](#0-3) 

5. The repository query becomes `WHERE topic_id = ? AND consensus_timestamp >= 0`, which matches every row for the topic. Without a limit, `setMaxResults` is never called. [5](#0-4) 

6. `TopicMessageServiceImpl` applies `flux.take(limit)` only when `filter.hasLimit()` is true (`limit > 0`). With `limit = 0` (the proto3 default), no cap is applied. [6](#0-5) 

7. The only gRPC interceptor sets an endpoint context for table-usage tracking — no auth, no rate limiting. [7](#0-6) 

8. Rate limiting (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module, not in the `grpc` module. [8](#0-7) 

**Root cause:** `convertTimestamp()` has no lower-bound guard, and `TopicMessageFilter.isValidStartTime()` only rejects future timestamps. The combination allows epoch 0 to flow through as a valid `startTime`, producing an unbounded historical scan.

**Why existing checks fail:**
- `@Min(0)` explicitly permits `0`.
- `isValidStartTime()` only checks `startTime <= now()`, not `startTime >= some_reasonable_floor`.
- `convertTimestamp()` only handles positive overflow, not the semantically dangerous epoch-zero case.

### Impact Explanation
For any high-volume HCS topic (e.g., price-feed topics with millions of messages), a single unauthenticated request with `{seconds:0, nanos:0}` and no limit forces the server to: (a) execute a full per-topic table scan on `topic_message`, (b) page through all results via `PollingTopicMessageRetriever` in a loop until complete, and (c) stream all results over the gRPC connection. Concurrent such requests from multiple clients can saturate the database connection pool and exhaust server memory, constituting a practical Denial-of-Service.

### Likelihood Explanation
The gRPC endpoint is publicly reachable with no authentication. The attack requires only a standard gRPC client (e.g., `grpcurl`) and knowledge of any active topic ID (topic IDs are public on the Hedera network). The exploit is trivially repeatable and scriptable. The own test suite demonstrates the behavior works as described (`subscribeTopicBlocking` and `historicalMessages` tests both use `startTime(0)` and retrieve all messages). [9](#0-8) [10](#0-9) 

### Recommendation
1. **Enforce a minimum `startTime` floor** in `TopicMessageFilter.isValidStartTime()`: reject any `startTime` older than a configurable maximum lookback window (e.g., 30 days), or at minimum reject `startTime == 0`.
2. **Add a lower-bound guard in `convertTimestamp()`**: if `timestamp.getSeconds() == 0 && timestamp.getNanos() == 0`, treat it as "not set" or substitute `DomainUtils.now()`.
3. **Enforce a server-side maximum result cap** on the gRPC streaming path, independent of the client-supplied `limit`.
4. **Add rate limiting** to the gRPC module analogous to the `ThrottleConfiguration` in the `web3` module.

### Proof of Concept
```bash
# Using grpcurl against the mirror node gRPC endpoint
grpcurl -plaintext \
  -proto consensus_service.proto \
  -d '{
    "topicID": {"topicNum": 1234567},
    "consensusStartTime": {"seconds": 0, "nanos": 0}
  }' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Preconditions:** Network access to the gRPC port (default 5600). Knowledge of any valid topic ID (publicly available via the REST API or Hedera explorer).

**Trigger:** The request sets `consensusStartTime = {seconds:0, nanos:0}` with no `limit`. `convertTimestamp` returns `0`; validation passes; the DB query becomes `WHERE topic_id = 1234567 AND consensus_timestamp >= 0`; all historical messages are streamed.

**Result:** The server performs a full historical scan for the topic, streaming every message ever submitted. Repeating this from multiple clients causes sustained database load and potential service degradation.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L62-65)
```java
        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L76-81)
```java
    private long convertTimestamp(Timestamp timestamp) {
        if (timestamp.getSeconds() >= 9223372035L) {
            return Long.MAX_VALUE;
        }
        return DomainUtils.timestampInNanosMax(timestamp);
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L38-53)
```java
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-22)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-32)
```java
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/controller/ConsensusControllerTest.java (L148-159)
```java
        ConsensusTopicQuery query = ConsensusTopicQuery.newBuilder()
                .setLimit(3L)
                .setConsensusStartTime(Timestamp.newBuilder().setSeconds(0).build())
                .setTopicID(TOPIC_ID.toTopicID())
                .build();

        assertThat(blockingService.subscribeTopic(query))
                .toIterable()
                .hasSize(3)
                .containsSequence(
                        grpcResponse(topicMessage1), grpcResponse(topicMessage2), grpcResponse(topicMessage3));
    }
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/service/TopicMessageServiceTest.java (L200-214)
```java
    @Test
    void historicalMessages() {
        var topicMessage1 = domainBuilder.topicMessage().block();
        var topicMessage2 = domainBuilder.topicMessage().block();
        var topicMessage3 = domainBuilder.topicMessage().block();

        TopicMessageFilter filter =
                TopicMessageFilter.builder().startTime(0).topicId(TOPIC_ID).build();

        StepVerifier.withVirtualTime(() -> topicMessageService.subscribeTopic(filter))
                .thenAwait(WAIT)
                .expectNext(topicMessage1, topicMessage2, topicMessage3)
                .thenCancel()
                .verify(WAIT);
    }
```
