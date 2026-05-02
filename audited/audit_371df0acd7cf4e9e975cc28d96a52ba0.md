### Title
Unbounded Subscription Accumulation with Infinite Retry Exhausts DB Connection Pool During Network Partition

### Summary
The gRPC `subscribeTopic` endpoint accepts an unlimited number of concurrent subscriptions from unauthenticated external users. The `PollingTopicMessageRetriever.retrieve()` implementation uses `Retry.backoff(Long.MAX_VALUE, ...)` — infinite retries — with no global subscription cap enforced. During a database network partition, an attacker who floods the service with new subscriptions causes all of them to simultaneously hammer the DB connection pool on retry, preventing the service from recovering when the partition heals.

### Finding Description

**Code path and root cause:**

`TopicMessageServiceImpl.subscribeTopic()` ( [1](#0-0) ) maintains `subscriberCount` as a plain `AtomicLong` metric gauge. It is incremented on subscribe and decremented on completion, but **never checked against any maximum**: [2](#0-1) 

There is no rejection path based on subscriber count. The only connection-level guard is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`: [3](#0-2) 

This limits calls **per TCP connection**, not total across all connections. An attacker opening N connections gets 5N concurrent subscriptions with no further restriction.

Each subscription's historical retrieval path calls `PollingTopicMessageRetriever.retrieve()`, which configures infinite retries: [4](#0-3) 

`Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1))` means every subscription retries forever (with exponential backoff) on DB errors. The 60-second `timeout` only fires if no message is emitted — during a partition with no messages, the timeout clock resets on each retry attempt, so subscriptions can persist well beyond 60 seconds.

Additionally, the safety-check path in `missingMessages()` also calls `retrieve(gapFilter, false)` (unthrottled): [5](#0-4) 

The unthrottled path uses `maxPageSize = 5000` and `pollingFrequency = 20ms`: [6](#0-5) 

**Exploit flow:**

1. Attacker opens M gRPC connections to the public endpoint (no authentication required — confirmed by the absence of any `ServerInterceptor` doing auth in production code; the only interceptor is a test-only `GrpcInterceptor` that sets endpoint context). [7](#0-6) 
2. Each connection opens 5 `subscribeTopic` streams → M×5 total subscriptions, all accepted.
3. A network partition isolates the DB. Existing subscriptions begin retrying via `Retry.backoff(Long.MAX_VALUE, ...)`.
4. Attacker continues opening new connections and subscriptions throughout the partition. Each new subscription immediately begins its own retry loop.
5. All retry attempts compete for the shared DB connection pool. The `boundedElastic()` scheduler queues tasks up to its internal limit (default: 100,000 tasks).
6. When the partition heals, the DB connection pool is saturated by the accumulated retry storm from all subscriptions. Legitimate traffic cannot acquire connections; the service cannot process real messages.

### Impact Explanation

**Service unavailability / denial of recovery.** During a DB partition — already a degraded state — an attacker can prevent the service from recovering when the partition heals. The DB connection pool remains exhausted by the retry storm from accumulated subscriptions. All legitimate subscribers are starved. The `hiero_mirror_grpc_subscribers` metric will show an anomalous spike, but there is no automated circuit-breaker to shed load. Severity: **High** (targeted DoS against a public, unauthenticated endpoint that compounds an existing failure mode).

### Likelihood Explanation

**High feasibility.** The gRPC endpoint is publicly reachable with no authentication, no per-IP rate limiting, and no global subscription cap. Opening thousands of gRPC connections is achievable with standard tooling (e.g., `grpcurl` in a loop, or any gRPC client library). The attacker does not need any credentials, topic ownership, or special knowledge — only the server address and a valid topic ID (or `checkTopicExists = false` in some deployments). The attack is repeatable and can be automated. The network partition scenario is a realistic operational event (DB failover, maintenance, cloud networking issue).

### Recommendation

1. **Enforce a global maximum subscriber count.** Check `subscriberCount` against a configurable limit in `subscribeTopic()` before accepting the subscription, returning `RESOURCE_EXHAUSTED` gRPC status when exceeded.
2. **Add per-IP or per-connection subscription rate limiting** via a gRPC `ServerInterceptor` using a token-bucket (similar to the existing `ThrottleManagerImpl` in the web3 module). [8](#0-7) 
3. **Cap retry attempts** in `PollingTopicMessageRetriever`. Replace `Long.MAX_VALUE` with a bounded retry count (e.g., 10–20 attempts), after which the subscription terminates with an error, forcing the client to reconnect with its own backoff. [9](#0-8) 
4. **Limit total connections per IP** at the Netty/proxy layer in addition to `maxConcurrentCallsPerConnection`.

### Proof of Concept

```bash
# Preconditions: gRPC server running, DB reachable, valid topicNum known
# Step 1: Simulate DB partition (e.g., block DB port via iptables on server)

# Step 2: Flood subscriptions from attacker machine (no credentials needed)
for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
# Each background process opens 1 connection × 1 stream = 200 subscriptions
# With 5 concurrent calls/connection, use a client that multiplexes:
# 200 connections × 5 streams = 1000 concurrent retrying subscriptions

# Step 3: Restore DB partition
# Expected result: DB connection pool saturated by retry storm;
# hiero_mirror_grpc_retriever metric shows sustained error rate;
# legitimate subscribers receive no messages / timeout;
# service does not recover until subscriptions time out (up to 60s each,
# but attacker keeps opening new ones to maintain pressure).
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L149-149)
```java
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L58-59)
```java
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L39-46)
```java
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-43)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

```
