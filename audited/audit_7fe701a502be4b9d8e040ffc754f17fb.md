### Title
Unauthenticated Subscription Flood via Short-Lived `consensusEndTime` Causes Resource Exhaustion in `subscribeTopic`

### Summary
The `subscribeTopic` endpoint in `ConsensusController` accepts `ConsensusTopicQuery` requests from any unauthenticated caller with no rate limiting or per-IP connection cap at the application layer. A critical amplifier exists in `TopicMessageServiceImpl`: subscriptions with a near-future `consensusEndTime` are not terminated until `endTime + endTimeInterval` (default 30 s) has elapsed, meaning each "1-second" subscription actually holds server resources for ~31 seconds. An attacker opening many TCP connections and cycling short-lived subscriptions can exhaust the DB connection pool, thread pool, and reactive scheduler, degrading or denying service to all legitimate subscribers.

### Finding Description

**Code path – controller entry point**

`ConsensusController.subscribeTopic()` (lines 43–53) accepts any `ConsensusTopicQuery` with no authentication check, no rate limit, and no cap on total active subscriptions: [1](#0-0) 

`toFilter()` (lines 55–73) accepts any `consensusEndTime` value that is merely greater than `startTime` (enforced by `TopicMessageFilter.isValidEndTime()`): [2](#0-1) 

**Root cause – `endTimeInterval` amplification**

`TopicMessageServiceImpl.isComplete()` (lines 203–215) does not terminate a subscription when `endTime` is reached. It returns `true` only when `endTime + endTimeInterval < now`: [3](#0-2) 

`pastEndTime()` (lines 123–131) polls `isComplete()` with a fixed delay of `endTimeInterval` (default **30 s**): [4](#0-3) 

`endTimeInterval` defaults to 30 s: [5](#0-4) 

A subscription with `endTime = now + 1 s` therefore stays alive for approximately **31 seconds**, not 1 second.

**Per-subscription resource cost**

Each subscription triggers:
1. A historical DB query via `topicMessageRetriever.retrieve()` (line 63).
2. A safety-check DB query after 1 s (lines 67–70).
3. A `TopicContext` object, a reactive pipeline, and a listener registration held for the full ~31 s lifetime. [6](#0-5) 

**Existing checks are insufficient**

- `maxConcurrentCallsPerConnection = 5` (default) limits concurrent calls **per TCP connection**, not globally per IP: [7](#0-6) 

  An attacker opens N TCP connections → N × 5 concurrent subscriptions with no application-level cap.

- The only gRPC interceptor sets endpoint context for table-usage tracking only — no rate limiting: [8](#0-7) 

- The GCP gateway `maxRatePerEndpoint: 250` is optional infrastructure config, absent in the docker-compose deployment and not enforced at the application layer: [9](#0-8) 

- `TopicMessageFilter.isValidEndTime()` only checks `endTime > startTime`, imposing no minimum duration: [10](#0-9) 

- `subscriberCount` is a metrics gauge only — it is never checked against a maximum: [11](#0-10) 

### Impact Explanation

Each attacker-controlled subscription holds a DB connection slot (historical query + safety-check query), a bounded-elastic scheduler thread, and heap memory for ~31 s. With the DB `statementTimeout` at 10 s and the default DB pool size, a modest number of concurrent subscriptions exhausts the pool, causing all subsequent subscriptions (including legitimate ones) to queue or fail. This degrades or denies the HCS topic subscription service — the primary real-time data path for Hedera Consensus Service clients — without affecting the consensus nodes themselves but breaking the mirror node's ability to serve any subscriber.

### Likelihood Explanation

The attack requires zero privileges: no API key, no account, no authentication of any kind. The gRPC port (5600) is publicly exposed. A single attacker machine can open hundreds of TCP connections and saturate the server with thousands of concurrent subscriptions using a trivial script (e.g., `grpcurl` in a loop or any gRPC client library). The 30 s `endTimeInterval` amplifier means the attacker does not even need to cycle rapidly — a single burst of connections sustains the load for 30+ seconds per wave. The attack is repeatable, stateless, and requires no knowledge of internal state.

### Recommendation

1. **Enforce a global maximum active subscription count** — check `subscriberCount` against a configurable ceiling in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` when exceeded.
2. **Add per-IP subscription rate limiting** via a gRPC `ServerInterceptor` using a token-bucket (e.g., Bucket4j, as already used in the `web3` module) keyed on the client's remote address.
3. **Enforce a minimum `endTime` distance** (e.g., ≥ 5 s from `now`) in `TopicMessageFilter.isValidEndTime()` to prevent trivially short subscriptions from being used as a cycling mechanism.
4. **Reduce or make `endTimeInterval` adaptive** — the 30 s default dramatically extends the lifetime of short-lived subscriptions beyond what the client requested.
5. **Add a per-IP TCP connection limit** at the Netty layer via `NettyServerBuilder` to bound the multiplier effect.

### Proof of Concept

```bash
# Open 50 parallel connections, each with 5 concurrent subscriptions (250 total),
# each with endTime = now + 1s. Due to endTimeInterval=30s, each lives ~31s.
# Repeat every 5s to maintain sustained load.

TOPIC='{"topicNum": 1}'
END_TIME=$(python3 -c "import time,json; print(json.dumps({'seconds': int(time.time()+1)}))")

for i in $(seq 1 50); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d "{\"topicID\": $TOPIC, \"consensusEndTime\": $END_TIME}" \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observe: DB connection pool exhausted, legitimate subscribers receive errors,
# hiero.mirror.grpc.subscribers gauge spikes to 250+.
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L67-70)
```java
        if (query.hasConsensusEndTime()) {
            long endTime = convertTimestamp(query.getConsensusEndTime());
            filter.endTime(endTime);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-70)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L22-22)
```java
    private Duration endTimeInterval = Duration.ofSeconds(30);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L16-22)
```java
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-46)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }
```
