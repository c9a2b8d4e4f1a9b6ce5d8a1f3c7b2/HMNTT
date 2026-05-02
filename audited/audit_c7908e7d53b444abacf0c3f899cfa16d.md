### Title
Unauthenticated Unbounded gRPC Stream Subscription Causes Resource Exhaustion and Subscriber Starvation

### Summary
Any unauthenticated external client can call `subscribeTopic()` with `limit=0` (no message cap) and omit `consensusEndTime`, causing the server to hold a reactive stream open indefinitely per call. Because there is no per-IP connection cap, no global subscriber ceiling, and no authentication gate on the gRPC endpoint, an attacker can open arbitrarily many connections (each carrying up to 5 concurrent calls) to exhaust server threads, database polling slots, and Redis listener capacity, starving legitimate subscribers from receiving fund-critical consensus messages.

### Finding Description

**Entry point — no authentication:**

`ConsensusController.subscribeTopic()` accepts any `ConsensusTopicQuery` with zero authentication or authorization checks. [1](#0-0) 

The only `ServerInterceptor` registered is `GrpcInterceptor`, which only sets an endpoint-context thread-local and passes the call through unconditionally. [2](#0-1) 

**`limit=0` disables the message cap:**

`toFilter()` passes `query.getLimit()` directly to `TopicMessageFilter.builder().limit(...)`. The protobuf default for an unset `uint64` field is `0`. [3](#0-2) 

`hasLimit()` returns `true` only when `limit > 0`, so `limit=0` means no `flux.take()` is ever applied. [4](#0-3) [5](#0-4) 

**No `endTime` → `Flux.never()` → stream never terminates:**

When `endTime` is `null`, `pastEndTime()` returns `Flux.never()`, so the `takeUntilOther` signal that would close the live stream never fires. [6](#0-5) 

The combined flux therefore runs forever: [7](#0-6) 

**Per-connection limit is trivially bypassed:**

`maxConcurrentCallsPerConnection` defaults to 5, but this is a *per-connection* ceiling with no cap on the number of connections. [8](#0-7) [9](#0-8) 

**`subscriberCount` is a metric gauge only — not enforced:**

The subscriber counter is used solely for Prometheus metrics; it imposes no admission-control limit. [10](#0-9) 

**No rate limiting on the gRPC module:**

The `ThrottleConfiguration` / `ThrottleManagerImpl` rate-limiting infrastructure exists only in the `web3` module; the `grpc` module has no equivalent. [11](#0-10) 

### Impact Explanation

Each indefinite subscription holds:
- A Netty channel slot and associated thread resources.
- A periodic database polling loop (every 2 s by default via `RetrieverProperties.pollingFrequency`).
- A Redis listener subscription slot (default listener type is `REDIS`).

An attacker opening `N` TCP connections × 5 calls each creates `5N` permanent polling loops. As `N` grows, the database connection pool saturates (alerting threshold is 75% utilization per the Helm alert rules), the Redis subscriber count spikes, and legitimate clients begin receiving errors or stalled streams. Because the gRPC service delivers consensus messages used to confirm fund transfers, starvation of legitimate subscribers means they cannot observe transaction finality — a direct operational impact on fund-critical workflows.

### Likelihood Explanation

The attack requires zero privileges, zero tokens, and zero knowledge beyond the publicly documented gRPC endpoint and protobuf schema (the README even provides a `grpcurl` example with `"limit": 0`). It is trivially scriptable: a single shell loop opening connections with `grpcurl` or any gRPC client suffices. The attack is repeatable and persistent — streams stay open until the server is restarted or the attacker's TCP connections are dropped. No exploit tooling beyond standard gRPC clients is needed. [12](#0-11) 

### Recommendation

1. **Enforce a maximum concurrent subscriber count** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold (e.g., return `RESOURCE_EXHAUSTED`).
2. **Add per-IP / per-connection subscription rate limiting** via a gRPC `ServerInterceptor` using the same Bucket4j pattern already used in the `web3` module.
3. **Cap the maximum stream duration**: if `endTime` is absent, inject a server-side maximum (e.g., 24 h) so streams cannot be held open indefinitely.
4. **Enforce a minimum `limit` floor or a maximum `limit=0` session count** so unlimited subscriptions are restricted to authenticated/trusted callers.
5. **Add a global connection limit** to `NettyServerBuilder` (e.g., `maxConnectionAge`, `maxConnectionIdle`) to bound resource consumption per client.

### Proof of Concept

```bash
# Open 100 connections, each with 5 unlimited subscriptions (500 permanent streams)
for i in $(seq 1 100); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observe subscriberCount metric climbing without bound:
curl http://<mirror-node-host>:8080/actuator/prometheus \
  | grep hiero_mirror_grpc_subscribers

# Legitimate subscriber now experiences stalled or errored stream
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 41110}, "limit": 10}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# → RESOURCE_EXHAUSTED or indefinite hang as DB pool / Redis slots are saturated
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-56)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L72-85)
```java
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-20)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";
```

**File:** docs/grpc/README.md (L14-16)
```markdown
Example invocation using [grpcurl](https://github.com/fullstorydev/grpcurl):

`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```
