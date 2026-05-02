### Title
Per-Connection gRPC Stream Cap Bypassed via Multiple TCP Connections — Unauthenticated Resource Exhaustion

### Summary
The gRPC server enforces a limit of 5 concurrent calls **per TCP connection** via `maxConcurrentCallsPerConnection`, but imposes no limit on the total number of TCP connections from a single client, no global cap on concurrent streams, and requires no authentication. An unprivileged attacker can open an arbitrary number of TCP connections and saturate the server with `N × 5` concurrent `subscribeTopic` streams, exhausting the thread pool, database connection pool, and Redis listener resources.

### Finding Description

**Code path and root cause:**

`NettyProperties.java` defines the only server-side concurrency control: [1](#0-0) 

`GrpcConfiguration.java` applies it to the Netty server builder — and nothing else: [2](#0-1) 

No `maxConnectionAge`, `maxConnectionIdle`, `permitKeepAliveWithoutCalls`, per-IP connection cap, or global stream cap is configured anywhere in the gRPC module. A grep across all `grpc/**` files for `maxConnections`, `maxConnectionAge`, `maxConnectionIdle`, `permitKeepAlive`, and `flowControl` returns zero matches.

**The `subscriberCount` counter is metrics-only and never enforces a cap:** [3](#0-2) [4](#0-3) 

The counter is incremented and decremented but never compared against a maximum; no rejection path exists.

**No authentication on the gRPC endpoint:**

A search across all `grpc/src/main/java/**/*.java` for `authentication`, `Authorization`, `ServerInterceptor`, and `security` returns a single irrelevant match in a domain filter class. The `ConsensusController.subscribeTopic` method accepts any caller with no credential check: [5](#0-4) 

**Exploit flow:**

1. Attacker opens connection C₁ and calls `subscribeTopic` 5 times (hits per-connection cap).
2. Attacker opens connection C₂ and calls `subscribeTopic` 5 more times.
3. Repeat for C₃ … Cₙ — the server accepts every new TCP connection and every new stream.
4. Each stream triggers: a DB existence check, a historical message retrieval query, a live Redis listener subscription, and a safety-check scheduled task on `Schedulers.boundedElastic()`. [6](#0-5) 

### Impact Explanation

Each open `subscribeTopic` stream holds a slot in the shared `applicationTaskExecutor` thread pool, a database connection from the pool (for historical retrieval polling), and a Redis pub/sub listener. With no global cap, an attacker can exhaust all three resource pools simultaneously. Legitimate subscribers receive `RESOURCE_EXHAUSTED` or hang indefinitely. The service becomes effectively unavailable — a complete denial of service against the gRPC API. Severity: **High**.

### Likelihood Explanation

The attack requires no credentials, no special tooling, and no prior knowledge beyond the publicly documented port (5600) and protobuf schema (published in the repo). A single attacker machine with a standard gRPC client library (e.g., `grpcurl` in a loop, or a trivial Go/Python script) can open hundreds of connections. The attack is repeatable and stateless from the attacker's perspective. Likelihood: **High**.

### Recommendation

1. **Add a global concurrent-stream cap** in `GrpcConfiguration` using a `ServerInterceptor` that tracks total active calls via an `AtomicInteger` and rejects new calls with `Status.RESOURCE_EXHAUSTED` when the global limit is reached.
2. **Add a per-IP connection limit** via Netty's `maxConnectionsPerIp` or an external load-balancer rule.
3. **Configure connection lifetime bounds** on the `NettyServerBuilder`:
   - `maxConnectionAge` — forces periodic reconnection, preventing indefinite stream accumulation.
   - `maxConnectionIdle` — closes idle connections.
4. **Expose `subscriberCount` as an enforced gate**, not just a metric: reject new subscriptions when the count exceeds a configurable global maximum.
5. **Add `NettyProperties` fields** for the above parameters so they are operator-configurable alongside `maxConcurrentCallsPerConnection`.

### Proof of Concept

```bash
# Open 20 TCP connections, each with 5 indefinite subscribeTopic streams = 100 total streams
for i in $(seq 1 20); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}}' \
      <host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
# All 100 streams are accepted; server thread pool, DB pool, and Redis listeners saturate.
# Legitimate clients receive RESOURCE_EXHAUSTED or timeout.
```

No credentials are required. The attack scales linearly with the number of connections the attacker's OS can open.

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-73)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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
